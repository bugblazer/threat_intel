/**
 * techniques.routes.js — /api/v1/techniques
 *
 * GET  /             — full technique list, filterable by tactic
 * GET  /heatmap      — technique_frequency view (powers ATT&CK heatmap)
 * GET  /tactics      — distinct tactic list for UI filter menus
 * GET  /:techniqueId — single technique + linked CVEs + linked IOCs
 * GET  /search       — trigram fuzzy search on name and technique_id
 *
 * DB Concepts demonstrated:
 *   Views   — technique_frequency view used by /heatmap
 *   Indexing — tactic B-tree index, platforms GIN, technique_id unique index
 *   JSONB   — platforms filtered with @> operator
 */

const router          = require('express').Router();
const { getPool }     = require('../db/db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { asyncHandler, paginate } = require('../middleware/common');
const { logAudit } = require('../lib/audit');

router.use(requireAuth);
router.use(paginate);

// ── GET /api/v1/techniques ────────────────────────────────────────────────────
router.get('/', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { tactic, platform, is_subtechnique } = req.query;
  const { limit, offset } = req.pagination;

  let query = db('techniques').select(
    'id', 'technique_id', 'name', 'tactic',
    'platforms', 'is_subtechnique', 'parent_technique_id',
  );

  // B-tree index on tactic (migration 004)
  if (tactic) query = query.where('tactic', tactic);

  // GIN JSONB index: WHERE platforms @> '["Windows"]'
  if (platform) {
    query = query.whereRaw('platforms @> ?::jsonb', [JSON.stringify([platform])]);
  }

  if (is_subtechnique !== undefined) {
    query = query.where('is_subtechnique', is_subtechnique === 'true');
  }

  const [{ count }] = await query.clone().count('id as count');
  const rows = await query.orderBy('technique_id').limit(limit).offset(offset);

  res.json({ total: Number(count), page: req.pagination.page, limit, data: rows });
}));

// ── GET /api/v1/techniques/heatmap ────────────────────────────────────────────
// DB Concept: Views — reads from technique_frequency view
// Returns the full matrix (no pagination) — the heatmap needs all tactics at once
router.get('/heatmap', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);

  // Cast bigint COUNT columns to int in SQL — Knex serialises PG bigints as
  // strings to avoid JS precision loss, which breaks Math.max on the frontend.
  const rows = await db.raw(`
    SELECT
      tf.technique_id,
      tf.name,
      tf.tactic,
      tf.is_subtechnique,
      tf.platforms,
      tf.ioc_count::int       AS ioc_count,
      tf.cve_count::int       AS cve_count,
      tf.total_frequency::int AS total_frequency,
      t.detection_status,
      t.detection_notes,
      t.detection_updated_by,
      t.detection_updated_at
    FROM technique_frequency tf
    JOIN techniques t ON t.technique_id = tf.technique_id
  `);

  const data = rows.rows;

  // Group by tactic for the frontend matrix renderer
  const byTactic = data.reduce((acc, row) => {
    const t = row.tactic || 'unknown';
    if (!acc[t]) acc[t] = [];
    acc[t].push(row);
    return acc;
  }, {});

  res.json({ data, byTactic });
}));

// ── GET /api/v1/techniques/tactics ────────────────────────────────────────────
router.get('/tactics', asyncHandler(async (req, res) => {
  const db   = getPool(req.user.role);
  const rows = await db('techniques')
    .distinct('tactic')
    .whereNotNull('tactic')
    .orderBy('tactic');

  res.json({ data: rows.map(r => r.tactic) });
}));

// ── GET /api/v1/techniques/search ─────────────────────────────────────────────
// Trigram fuzzy search — uses GiST gist_trgm_ops index on name
router.get('/search', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { q } = req.query;

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Query param `q` must be at least 2 characters' });
  }

  const { limit, offset } = req.pagination;

  const rows = await db.raw(`
    SELECT
      technique_id, name, tactic, platforms, is_subtechnique,
      similarity(name, ?) AS sim
    FROM techniques
    WHERE name % ?
       OR technique_id ILIKE ?
    ORDER BY sim DESC, technique_id
    LIMIT ? OFFSET ?
  `, [q, q, `%${q}%`, limit, offset]);

  res.json({ query: q, data: rows.rows });
}));

// ── PATCH /api/v1/techniques/:techniqueId/coverage ────────────────────────────
// Set detection coverage for a technique. Contributors and admins only —
// enforced at the DB layer too (only those roles hold UPDATE on techniques).
const DETECTION_STATES = ['none', 'partial', 'detected'];

router.patch('/:techniqueId/coverage', requireRole('contributor', 'admin'), asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { detection_status, detection_notes } = req.body;

  if (!DETECTION_STATES.includes(detection_status)) {
    return res.status(400).json({ error: `detection_status must be one of: ${DETECTION_STATES.join(', ')}` });
  }

  const techId = req.params.techniqueId.toUpperCase();
  const before = await db('techniques').select('detection_status').where({ technique_id: techId }).first();
  if (!before) return res.status(404).json({ error: 'Technique not found' });

  const now = new Date();
  const updates = {
    detection_status,
    detection_updated_by: req.user.email,
    detection_updated_at: now,
    updated_at: now,
  };
  if (detection_notes !== undefined) updates.detection_notes = detection_notes;

  const [updated] = await db('techniques')
    .where({ technique_id: techId })
    .update(updates)
    .returning(['technique_id', 'detection_status', 'detection_notes', 'detection_updated_by', 'detection_updated_at']);

  // Audit via the admin pool — audit_log is only writable by threat_admin,
  // whereas this request may run on the contributor pool.
  await logAudit(getPool('admin'), req, {
    action: 'technique.coverage_changed', targetType: 'technique', targetId: techId,
    detail: { from: before.detection_status, to: detection_status },
  });

  res.json(updated);
}));

// ── GET /api/v1/techniques/:techniqueId ──────────────────────────────────────
router.get('/:techniqueId', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const technique = await db('techniques')
    .where({ technique_id: req.params.techniqueId.toUpperCase() })
    .first();

  if (!technique) return res.status(404).json({ error: 'Technique not found' });

  // Linked CVEs (via join table)
  const cves = await db('cve_technique_map as ctm')
    .join('cves as c', 'c.id', 'ctm.cve_id')
    .where('ctm.technique_id', technique.id)
    .select('c.cve_id', 'c.description', 'c.cvss_score', 'c.severity', 'ctm.confidence_score')
    .orderBy('c.cvss_score', 'desc')
    .limit(20);

  // Linked IOCs
  const iocs = await db('iocs')
    .where({ linked_technique_id: technique.id })
    .select('value', 'type', 'source_feed', 'malware_family', 'last_seen')
    .orderBy('last_seen', 'desc')
    .limit(20);

  // Sub-techniques (if this is a parent)
  const subTechniques = await db('techniques')
    .where({ parent_technique_id: technique.technique_id })
    .select('technique_id', 'name', 'tactic');

  res.json({ ...technique, cves, iocs, subTechniques });
}));

module.exports = router;
