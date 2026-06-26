/**
 * threatActors.routes.js — /api/v1/threat-actors
 *
 * GET  /         — list all threat actors with optional filters
 * GET  /search   — full-text search (tsvector on name + description)
 * GET  /:id      — single actor profile with their mapped TTPs and recent IOCs
 *
 * DB Concepts demonstrated:
 *   Full-Text Search — search_vector @@ plainto_tsquery on threat_actors
 *   JSONB            — meta column; technique_ids stored as text[]
 */

const router          = require('express').Router();
const { getPool }     = require('../db/db');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler, paginate } = require('../middleware/common');

router.use(requireAuth);
router.use(paginate);

// ── GET /api/v1/threat-actors ─────────────────────────────────────────────────
router.get('/', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { limit, offset } = req.pagination;
  const { country, motivation } = req.query;

let query = db('threat_actors');

  if (country)    query = query.where('country', country);
  if (motivation) query = query.where('motivation', motivation);

  const [{ count }] = await query
  .clone()
  .count('* as count');

const rows = await query
  .clone()
  .select(
    'id',
    'name',
    'aliases',
    'country',
    'motivation',
    'description',
    'technique_ids'
  )
  .orderBy('name')
  .limit(limit)
  .offset(offset);

  res.json({ total: Number(count), page: req.pagination.page, limit, data: rows });
}));

// ── GET /api/v1/threat-actors/search ─────────────────────────────────────────
// DB Concept: Full-Text Search on threat_actors.search_vector
router.get('/search', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { q } = req.query;

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Query param `q` must be at least 2 characters' });
  }

  const { limit, offset } = req.pagination;

  const result = await db.raw(`
    SELECT
      id, name, aliases, country, motivation, description, technique_ids,
      ts_rank(search_vector, plainto_tsquery('english', ?)) AS rank
    FROM threat_actors
    WHERE search_vector @@ plainto_tsquery('english', ?)
    ORDER BY rank DESC
    LIMIT ? OFFSET ?
  `, [q, q, limit, offset]);

  res.json({ query: q, data: result.rows });
}));

// ── GET /api/v1/threat-actors/:id ────────────────────────────────────────────
router.get('/:id', asyncHandler(async (req, res) => {
  const db    = getPool(req.user.role);
  const actor = await db('threat_actors').where('id', req.params.id).first();
  if (!actor) return res.status(404).json({ error: 'Threat actor not found' });

  // Resolve technique_ids[] to full technique objects
  const techniques = actor.technique_ids?.length
    ? await db('techniques')
        .whereIn('technique_id', actor.technique_ids)
        .select('technique_id', 'name', 'tactic', 'platforms')
    : [];

  // Recent IOCs that reference any of this actor's techniques
  const iocs = techniques.length
    ? await db('iocs as i')
        .join('techniques as t', 't.id', 'i.linked_technique_id')
        .whereIn('t.technique_id', actor.technique_ids)
        .select('i.value', 'i.type', 'i.source_feed', 'i.malware_family', 'i.last_seen', 't.name as technique_name')
        .orderBy('i.last_seen', 'desc')
        .limit(30)
    : [];

  res.json({ ...actor, techniques, recentIocs: iocs });
}));

module.exports = router;
