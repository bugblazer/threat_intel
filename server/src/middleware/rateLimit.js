/**
 * rateLimit.js — Small in-memory fixed-window rate limiter
 *
 * Used on the auth endpoints so a password can't be brute-forced and sign-up
 * can't be spammed. In-memory is enough here: there is one API process. If the
 * API is ever scaled out, the counters would need to move to Postgres or Redis.
 *
 *   router.post('/login', rateLimit({ windowMs: 15 * 60e3, max: 10, key: req => req.ip }), ...)
 *
 * Responds 429 with a Retry-After header once a key exceeds `max` hits in a window.
 */

function rateLimit({ windowMs, max, key = req => req.ip, message = 'Too many attempts. Try again later.' }) {
  const hits = new Map(); // key -> { count, resetAt }

  // Drop expired windows now and then so the map can't grow without bound.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, Math.min(windowMs, 60_000));
  sweep.unref?.();

  function middleware(req, res, next) {
    const k   = key(req);
    if (k == null) return next();
    const now = Date.now();
    let entry = hits.get(k);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(k, entry);
    }
    entry.count++;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return res.status(429).json({ error: message });
    }
    next();
  }

  middleware.reset = () => hits.clear(); // for tests
  return middleware;
}

module.exports = { rateLimit };
