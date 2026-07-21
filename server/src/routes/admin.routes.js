/**
 * admin.routes.js — /api/v1/admin
 *
 * All routes require admin role (enforced by requireRole middleware).
 *
 * GET  /users          — list all users
 * PATCH /users/:id     — update role or active status
 * DELETE /users/:id    — deactivate a user
 * POST /ingest         — trigger a manual ingestion run
 * GET  /ingest/status  — last ingestion run results (in-memory)
 *
 * DB Concepts demonstrated:
 *   Access Control — requireRole('admin') + RLS on users table
 */

const router      = require('express').Router();
const { getPool } = require('../db/db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/common');

// All admin routes require authentication AND admin role
router.use(requireAuth);
router.use(requireRole('admin'));

// In-memory store for last ingestion result (simple — no Redis needed for a course project)
let lastIngestionResult = null;
let ingestionRunning    = false;

// ── GET /api/v1/admin/users ───────────────────────────────────────────────────
router.get('/users', asyncHandler(async (req, res) => {
  // Admin pool bypasses RLS — sees all users
  const db   = getPool('admin');
  const rows = await db('users')
    .select('id', 'email', 'role', 'is_active', 'created_at')
    .orderBy('created_at', 'desc');

  res.json({ data: rows });
}));

// ── PATCH /api/v1/admin/users/:id ────────────────────────────────────────────
router.patch('/users/:id', asyncHandler(async (req, res) => {
  const db = getPool('admin');
  const { role, is_active } = req.body;
  const updates = {};

  if (role !== undefined) {
    if (!['readonly', 'contributor', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    updates.role = role;
  }
  if (is_active !== undefined) updates.is_active = Boolean(is_active);

  if (!Object.keys(updates).length) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  // Admin accounts cannot be deactivated (own or others').
  if (updates.is_active === false) {
    const target = await db('users').select('role').where('id', req.params.id).first();
    if (target?.role === 'admin') {
      return res.status(403).json({ error: 'Admin accounts cannot be deactivated' });
    }
  }

  updates.updated_at = new Date();
  const [updated] = await db('users')
    .where('id', req.params.id)
    .update(updates)
    .returning(['id', 'email', 'role', 'is_active']);

  if (!updated) return res.status(404).json({ error: 'User not found' });
  res.json(updated);
}));

// ── DELETE /api/v1/admin/users/:id ───────────────────────────────────────────
// Soft-delete: sets is_active = false (preserves audit trail)
router.delete('/users/:id', asyncHandler(async (req, res) => {
  const db = getPool('admin');

  // Admin accounts cannot be deactivated — neither your own nor another admin's.
  const target = await db('users').select('role').where('id', req.params.id).first();
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'admin') {
    return res.status(403).json({ error: 'Admin accounts cannot be deactivated' });
  }

  const [updated] = await db('users')
    .where('id', req.params.id)
    .update({ is_active: false, updated_at: new Date() })
    .returning(['id', 'email', 'is_active']);

  if (!updated) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'User deactivated', user: updated });
}));

// ── GET /api/v1/admin/role-requests ──────────────────────────────────────────
// List role-upgrade requests (pending by default; pass ?status=all for history).
router.get('/role-requests', asyncHandler(async (req, res) => {
  const db     = getPool('admin');
  const status = req.query.status || 'pending';

  const q = db('role_requests as r')
    .join('users as u', 'u.id', 'r.user_id')
    .select(
      'r.id', 'r.user_id', 'r.requested_role', 'r.status',
      'r.decided_by', 'r.decided_at', 'r.created_at',
      'u.email', 'u.role as current_role',
    )
    .orderBy('r.created_at', 'desc');

  if (status !== 'all') q.where('r.status', status);

  res.json({ data: await q });
}));

// ── PATCH /api/v1/admin/role-requests/:id ─────────────────────────────────────
// Approve or decline a pending request. Approval promotes the user.
router.patch('/role-requests/:id', asyncHandler(async (req, res) => {
  const db       = getPool('admin');
  const { action } = req.body; // 'approve' | 'decline'

  if (!['approve', 'decline'].includes(action)) {
    return res.status(400).json({ error: "action must be 'approve' or 'decline'" });
  }

  const request = await db('role_requests').where('id', req.params.id).first();
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  const now = new Date();

  await db.transaction(async (trx) => {
    await trx('role_requests')
      .where('id', request.id)
      .update({
        status:     action === 'approve' ? 'approved' : 'declined',
        decided_by: req.user.email,
        decided_at: now,
        updated_at: now,
      });

    if (action === 'approve') {
      await trx('users')
        .where('id', request.user_id)
        .update({ role: request.requested_role, updated_at: now });
    }
  });

  res.json({ message: `Request ${action === 'approve' ? 'approved' : 'declined'}` });
}));

// ── POST /api/v1/admin/ingest ─────────────────────────────────────────────────
// Trigger a manual ingestion run (runs in background, returns immediately)
router.post('/ingest', asyncHandler(async (req, res) => {
  if (ingestionRunning) {
    return res.status(409).json({ error: 'Ingestion already running' });
  }

  const { source, full_sync } = req.body;

  // Fire and forget — don't await (ingestion can take minutes)
  ingestionRunning = true;
  const { runIngestion } = require('../ingestion/index');
  runIngestion({ source, fullSync: full_sync === true })
    .then(result => {
      lastIngestionResult = { ...result, completedAt: new Date(), triggeredBy: req.user.email };
      ingestionRunning = false;
    })
    .catch(err => {
      lastIngestionResult = { error: err.message, completedAt: new Date() };
      ingestionRunning = false;
    });

  res.status(202).json({
    message: 'Ingestion started',
    source:  source ?? 'all',
    poll:    '/api/v1/admin/ingest/status',
  });
}));

// ── GET /api/v1/admin/ingest/status ──────────────────────────────────────────
router.get('/ingest/status', (req, res) => {
  res.json({
    running: ingestionRunning,
    last:    lastIngestionResult,
  });
});

module.exports = router;
