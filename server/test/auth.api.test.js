/**
 * End-to-end auth flow against a real database (the local dev DB from .env).
 * Skipped automatically when Postgres isn't reachable. Cleans up after itself.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

process.env.NODE_ENV = 'test';
const app = require('../src/index');
const { pools } = require('../src/db/db');

const email = `test-${crypto.randomUUID()}@example.test`;
const password = `pw-${crypto.randomUUID()}`;
let base, server, dbUp = false;

const cookieFrom = res => (res.headers.get('set-cookie') ?? '').split(';')[0]; // "ti_refresh=..."
const post = (path, { body, cookie, token } = {}) => fetch(`${base}${path}`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    ...(cookie ? { Cookie: cookie } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  },
  body: body ? JSON.stringify(body) : undefined,
});

test.before(async () => {
  try { await pools.admin.raw('SELECT 1 FROM refresh_tokens LIMIT 1'); dbUp = true; } catch { return; }
  await new Promise(r => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}/api/v1`;
});

test.after(async () => {
  if (dbUp) {
    await pools.admin('audit_log').where({ target_id: email }).del();
    await pools.admin('users').where({ email }).del(); // refresh_tokens cascade
  }
  server?.close();
  await Promise.all(Object.values(pools).map(p => p.destroy()));
});

test('signup sets an httpOnly, SameSite=Strict refresh cookie scoped to /api/v1/auth', async (t) => {
  if (!dbUp) return t.skip('database not available');
  const res = await post('/auth/signup', { body: { email, password } });
  assert.equal(res.status, 201);
  const raw = res.headers.get('set-cookie');
  assert.match(raw, /^ti_refresh=/);
  assert.match(raw, /HttpOnly/i);
  assert.match(raw, /SameSite=Strict/i);
  assert.match(raw, /Path=\/api\/v1\/auth/);
  const body = await res.json();
  assert.equal(body.user.role, 'readonly');
  assert.ok(body.token);
});

test('refresh rotates the token, and reusing an old one ends the whole session', async (t) => {
  if (!dbUp) return t.skip('database not available');
  const login = await post('/auth/login', { body: { email, password } });
  assert.equal(login.status, 200);
  const first = cookieFrom(login);

  const r1 = await post('/auth/refresh', { cookie: first });
  assert.equal(r1.status, 200);
  const second = cookieFrom(r1);
  assert.notEqual(second, first);
  assert.ok((await r1.json()).token);

  // The rotated-out token shows up again: treat it as stolen.
  const replay = await post('/auth/refresh', { cookie: first });
  assert.equal(replay.status, 401);

  // ...which also revoked the legitimate newer token in the same family.
  const afterReplay = await post('/auth/refresh', { cookie: second });
  assert.equal(afterReplay.status, 401);
});

test('logout revokes the session', async (t) => {
  if (!dbUp) return t.skip('database not available');
  const cookie = cookieFrom(await post('/auth/login', { body: { email, password } }));
  assert.equal((await post('/auth/logout', { cookie })).status, 204);
  assert.equal((await post('/auth/refresh', { cookie })).status, 401);
});

test('repeated wrong passwords for one account get rate limited', async (t) => {
  if (!dbUp) return t.skip('database not available');
  const statuses = [];
  for (let i = 0; i < 12; i++) {
    statuses.push((await post('/auth/login', { body: { email, password: 'wrong-password' } })).status);
  }
  // 2 successful logins above + 8 failures use up the 10-per-account window.
  assert.ok(statuses.includes(401));
  assert.equal(statuses.at(-1), 429);
});
