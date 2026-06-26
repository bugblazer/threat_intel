/**
 * common.js — Shared Express middleware
 *
 * errorHandler  — catch-all for unhandled errors; keeps stack traces out of prod responses
 * paginate      — parses ?page=&limit= into req.pagination for route handlers
 * asyncHandler  — wraps async route functions so errors propagate to errorHandler
 */

/**
 * Wrap an async route handler so thrown errors go to next(err).
 * Usage: router.get('/path', asyncHandler(async (req, res) => { ... }))
 */
function asyncHandler(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

/**
 * Parse pagination query params.
 * Attaches req.pagination = { page, limit, offset } to every request.
 */
function paginate(req, _res, next) {
  const page  = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 25));
  req.pagination = { page, limit, offset: (page - 1) * limit };
  next();
}

/**
 * Global error handler — must be the last middleware registered.
 */
function errorHandler(err, req, res, _next) {
  const isDev = process.env.NODE_ENV !== 'production';
  console.error(`[${new Date().toISOString()}] ERROR ${req.method} ${req.path}:`, err);

  // Knex/PG constraint errors
  if (err.code === '23505') {
    return res.status(409).json({ error: 'Duplicate record', detail: err.detail });
  }
  if (err.code === '23503') {
    return res.status(400).json({ error: 'Foreign key violation', detail: err.detail });
  }

  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    error:  err.message || 'Internal server error',
    ...(isDev && { stack: err.stack }),
  });
}

module.exports = { asyncHandler, paginate, errorHandler };
