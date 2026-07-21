/**
 * requests.routes.js — /api/v1/requests
 *
 * Self-service role-upgrade requests for the signed-in user.
 *
 * GET  /requests/me   — the current user's latest role request (or null)
 * POST /requests      — request the contributor role (read-only users only)
 *
 * Admin review of these requests lives in admin.routes.js.
 */

const router      = require('express').Router();
const { getPool } = require('../db/db');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/common');

router.use(requireAuth);

// ── GET /api/v1/requests/me ───────────────────────────────────────────────────
router.get('/me', asyncHandler(async (req, res) => {
  const db  = getPool('admin');
  const row = await db('role_requests')
    .where('user_id', req.user.id)
    .orderBy('created_at', 'desc')
    .first();

  res.json({ data: row ?? null });
}));

// ── POST /api/v1/requests ─────────────────────────────────────────────────────
// A read-only user asks to be upgraded to contributor.
router.post('/', asyncHandler(async (req, res) => {
  if (req.user.role !== 'readonly') {
    return res.status(400).json({
      error: 'Only read-only users can request the contributor role',
    });
  }

  const db = getPool('admin');

  // Block duplicate open requests.
  const pending = await db('role_requests')
    .where({ user_id: req.user.id, status: 'pending' })
    .first();
  if (pending) {
    return res.status(409).json({ error: 'You already have a pending request' });
  }

  const [row] = await db('role_requests')
    .insert({ user_id: req.user.id, requested_role: 'contributor', status: 'pending' })
    .returning(['id', 'user_id', 'requested_role', 'status', 'created_at']);

  res.status(201).json({ data: row });
}));

module.exports = router;
