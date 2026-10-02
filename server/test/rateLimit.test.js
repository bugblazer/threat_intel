const test = require('node:test');
const assert = require('node:assert/strict');
const { rateLimit } = require('../src/middleware/rateLimit');
const { readCookie } = require('../src/lib/refreshTokens');

function fakeRes() {
  return {
    statusCode: 200, headers: {}, body: null,
    set(k, v) { this.headers[k] = v; return this; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
  };
}

test('allows max hits per window, then answers 429 with Retry-After', () => {
  const limit = rateLimit({ windowMs: 60_000, max: 3 });
  const req = { ip: '203.0.113.7' };
  let passed = 0;
  for (let i = 0; i < 5; i++) {
    const res = fakeRes();
    limit(req, res, () => passed++);
    if (i >= 3) {
      assert.equal(res.statusCode, 429);
      assert.ok(Number(res.headers['Retry-After']) > 0);
    }
  }
  assert.equal(passed, 3);
});

test('keys are counted separately and a null key is never limited', () => {
  const limit = rateLimit({ windowMs: 60_000, max: 1, key: req => req.email ?? null });
  let passed = 0;
  for (const email of ['a@x.io', 'b@x.io', undefined, undefined]) limit({ email }, fakeRes(), () => passed++);
  assert.equal(passed, 4);
});

test('readCookie finds the refresh cookie among others', () => {
  assert.equal(readCookie({ headers: { cookie: 'theme=dark; ti_refresh=abc%2D123; x=1' } }), 'abc-123');
  assert.equal(readCookie({ headers: {} }), null);
});
