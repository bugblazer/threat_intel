/**
 * auth.routes.js — /api/v1/auth
 *
 * POST /login     — exchange email+password for a JWT
 * POST /register  — create a new user (admin only after first user exists)
 *
 * DB Concept: Access Control
 * Passwords are hashed with bcrypt. The JWT payload carries the PG role
 * so downstream route handlers can select the right connection pool.
 */

const router       = require('express').Router();
const bcrypt       = require('bcrypt');
const { getPool }  = require('../db/db');
const { signToken, requireAuth, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/common');
const { logAudit } = require('../lib/audit');

const SALT_ROUNDS = 12;

// ── POST /api/v1/auth/login ──────────────────────────────────────────────────
router.post('/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const db   = getPool('admin'); // users table — need admin pool (RLS bypassed)
  const user = await db('users').where({ email: email.toLowerCase() }).first();

  if (!user || !user.is_active) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = signToken(user);
  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
}));

// ── POST /api/v1/auth/signup ─────────────────────────────────────────────────
// Public self-registration. Anyone can create an account, but it is ALWAYS a
// read-only user — the requested role is ignored. To gain more privileges a
// read-only user must request the contributor role and have an admin approve it.
router.post('/signup', asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const db       = getPool('admin');
  const existing = await db('users').where({ email: email.toLowerCase() }).first();
  if (existing) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
  const [user] = await db('users')
    .insert({ email: email.toLowerCase(), password_hash, role: 'readonly' })
    .returning(['id', 'email', 'role']);

  // The new user is the actor for their own signup.
  await logAudit(db, { user: { id: user.id, email: user.email } }, {
    action: 'user.signed_up', targetType: 'user', targetId: user.email, detail: { role: 'readonly' },
  });

  const token = signToken(user);
  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
}));

// ── POST /api/v1/auth/register ───────────────────────────────────────────────
// Admin-only user creation (any role). First-ever user gets admin.
router.post('/register', asyncHandler(async (req, res) => {
  const { email, password, role = 'readonly' } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  // Enforce the password policy on the server too — the client-side check
  // in AdminPage is trivially bypassed with a direct API call.
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (!['readonly', 'contributor', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  const db    = getPool('admin');
  const count = await db('users').count('id as n').first();

  // If users already exist, require admin auth
  if (Number(count.n) > 0) {
    // Manually run auth middleware inline
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Admin auth required to register new users' });
    }
    // Let the requireAuth + requireRole middleware handle this on a separate route
    // For simplicity here: decode token and check role
    const jwt    = require('jsonwebtoken');
    const secret = process.env.JWT_SECRET || 'dev_secret_change_me';
    let decoded;
    try { decoded = jwt.verify(header.slice(7), secret); }
    catch { return res.status(401).json({ error: 'Invalid token' }); }
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can create new users' });
    }
  }

  const existing = await db('users').where({ email: email.toLowerCase() }).first();
  if (existing) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
  const [user] = await db('users')
    .insert({ email: email.toLowerCase(), password_hash, role })
    .returning(['id', 'email', 'role']);

  const token = signToken(user);
  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
}));

// ── GET /api/v1/auth/me ───────────────────────────────────────────────────────
// Returns the live user record. Because the role is carried in the JWT, a role
// change (e.g. an approved contributor request) wouldn't take effect until the
// user logged in again. To avoid that, we read the current role from the DB and,
// if it differs from the token, issue a fresh token so the new role activates on
// the next page load — no manual sign-out needed. Also enforces deactivation.
router.get('/me', requireAuth, asyncHandler(async (req, res) => {
  const db     = getPool('admin');
  const dbUser = await db('users')
    .select('id', 'email', 'role', 'is_active')
    .where('id', req.user.id)
    .first();

  if (!dbUser || !dbUser.is_active) {
    return res.status(401).json({ error: 'Account is inactive' });
  }

  const payload = { user: { id: dbUser.id, email: dbUser.email, role: dbUser.role } };

  // Role drifted from what the token says — mint a fresh token with the new role.
  if (dbUser.role !== req.user.role) {
    payload.token = signToken(dbUser);
  }

  res.json(payload);
}));

module.exports = router;
