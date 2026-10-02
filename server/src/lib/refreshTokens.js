/**
 * refreshTokens.js — Rotating refresh tokens in an httpOnly cookie
 *
 * The access token (JWT) now lives for 15 minutes and only in the browser's
 * memory. To stay signed in, the client calls POST /auth/refresh, which reads
 * this cookie, rotates the refresh token and returns a new access token.
 *
 *   - The cookie is httpOnly (no script can read it), SameSite=Strict and scoped
 *     to /api/v1/auth, so it is only ever sent to the auth endpoints.
 *   - Only the SHA-256 of a token is stored; a database leak doesn't leak sessions.
 *   - Every refresh revokes the presented token and issues a new one in the same
 *     family. If a revoked token shows up again, someone has a copy of it, so the
 *     whole family is revoked and the user has to sign in again.
 *   - Each token lives 7 days; a family (one login) at most 30 days.
 */

const crypto = require('crypto');

const COOKIE_NAME   = 'ti_refresh';
const COOKIE_PATH   = '/api/v1/auth';
const TOKEN_DAYS    = Number(process.env.REFRESH_TOKEN_DAYS) || 7;
const SESSION_DAYS  = Number(process.env.SESSION_MAX_DAYS) || 30;
const DAY_MS        = 24 * 60 * 60 * 1000;

const hash = token => crypto.createHash('sha256').update(token).digest('hex');

/** Minimal Cookie header parser (avoids a dependency for one cookie). */
function readCookie(req, name = COOKIE_NAME) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      try { return decodeURIComponent(part.slice(eq + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

function cookieOptions(req, expires) {
  return {
    httpOnly: true,
    // Behind the Cloudflare Tunnel req.secure is true (trust proxy + X-Forwarded-Proto);
    // on plain-http localhost it's false, so the cookie still works in development.
    secure:   req.secure,
    sameSite: 'strict',
    path:     COOKIE_PATH,
    expires,
  };
}

async function insertToken(db, { userId, familyId, familyExpiresAt, userAgent }) {
  const token     = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Math.min(Date.now() + TOKEN_DAYS * DAY_MS, familyExpiresAt.getTime()));
  await db('refresh_tokens').insert({
    user_id:           userId,
    token_hash:        hash(token),
    family_id:         familyId,
    expires_at:        expiresAt,
    family_expires_at: familyExpiresAt,
    user_agent:        userAgent ? String(userAgent).slice(0, 255) : null,
  });
  return { token, expiresAt };
}

/** Start a new session (login/signup): new family, set the cookie. */
async function issueRefreshToken(db, req, res, userId) {
  const { token, expiresAt } = await insertToken(db, {
    userId,
    familyId:        crypto.randomUUID(),
    familyExpiresAt: new Date(Date.now() + SESSION_DAYS * DAY_MS),
    userAgent:       req.headers['user-agent'],
  });
  res.cookie(COOKIE_NAME, token, cookieOptions(req, expiresAt));
}

/**
 * Validate and rotate the cookie's refresh token.
 * Returns the user id on success, or null (and clears the cookie) on failure.
 */
async function rotateRefreshToken(db, req, res) {
  const presented = readCookie(req);
  if (!presented) return null;

  const row = await db('refresh_tokens').where({ token_hash: hash(presented) }).first();
  const now = new Date();

  if (!row) { clearRefreshCookie(req, res); return null; }

  if (row.revoked_at) {
    // Reuse of a rotated token: assume theft and end every session in this family.
    await db('refresh_tokens').where({ family_id: row.family_id }).whereNull('revoked_at').update({ revoked_at: now });
    clearRefreshCookie(req, res);
    return null;
  }

  if (row.expires_at <= now || row.family_expires_at <= now) {
    await db('refresh_tokens').where({ id: row.id }).update({ revoked_at: now });
    clearRefreshCookie(req, res);
    return null;
  }

  // Revoke-then-insert in one transaction so a token can only be rotated once.
  const rotated = await db.transaction(async (trx) => {
    const n = await trx('refresh_tokens').where({ id: row.id }).whereNull('revoked_at').update({ revoked_at: now });
    if (!n) return null; // lost a race with a parallel refresh using the same token
    return insertToken(trx, {
      userId:          row.user_id,
      familyId:        row.family_id,
      familyExpiresAt: row.family_expires_at,
      userAgent:       req.headers['user-agent'],
    });
  });
  if (!rotated) { clearRefreshCookie(req, res); return null; }

  res.cookie(COOKIE_NAME, rotated.token, cookieOptions(req, rotated.expiresAt));
  return row.user_id;
}

/** Sign out: revoke the presented token's family and clear the cookie. */
async function revokeRefreshToken(db, req, res) {
  const presented = readCookie(req);
  if (presented) {
    const row = await db('refresh_tokens').where({ token_hash: hash(presented) }).first();
    if (row) {
      await db('refresh_tokens').where({ family_id: row.family_id }).whereNull('revoked_at').update({ revoked_at: new Date() });
    }
  }
  clearRefreshCookie(req, res);
}

/** End every session for a user (e.g. when an admin deactivates them). */
function revokeAllForUser(db, userId) {
  return db('refresh_tokens').where({ user_id: userId }).whereNull('revoked_at').update({ revoked_at: new Date() });
}

function clearRefreshCookie(req, res) {
  res.clearCookie(COOKIE_NAME, { ...cookieOptions(req), expires: undefined });
}

module.exports = {
  COOKIE_NAME,
  readCookie,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllForUser,
};
