/**
 * auth.js — JWT Authentication Middleware
 *
 * Validates the Bearer token on protected routes and attaches
 * req.user = { id, email, role } for downstream handlers.
 *
 * DB Concept: Access Control
 * The role claim in the JWT maps directly to a PostgreSQL role.
 * Route handlers call getPool(req.user.role) to get the right
 * connection — so the DB enforces permissions, not just app code.
 */

const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  // Never allow the hardcoded fallback secret outside local development
  throw new Error('JWT_SECRET must be set in production');
}

/**
 * Middleware: require a valid JWT.
 * Attaches req.user on success; returns 401 on failure.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = header.slice(7);
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    return res.status(401).json({ error: msg });
  }
}

/**
 * Middleware factory: require a specific role (or one of several).
 * Always chain after requireAuth.
 *
 * Usage:
 *   router.delete('/users/:id', requireAuth, requireRole('admin'), handler)
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({
        error: `Forbidden — requires role: ${roles.join(' or ')}`,
      });
    }
    next();
  };
}

/**
 * Sign a new JWT for a user record.
 * @param {{ id, email, role }} user
 */
function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' },
  );
}

module.exports = { requireAuth, requireRole, signToken };
