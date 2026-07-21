/**
 * iocs.routes.js — /api/v1/iocs
 *
 * GET  /         — paginated list with filters (type, feed, malware family, date range)
 * GET  /search   — full-text + trigram search on IOC value (DB Concept: Full-Text Search)
 * GET  /stats    — aggregate counts by type and source_feed (for dashboard KPIs)
 * GET  /:id      — single IOC detail with linked CVE and technique
 *
 * DB Concepts demonstrated:
 *   Views    — active_iocs view (pre-joined with cves and techniques)
 *   Indexing — type, source_feed, last_seen, malware_family, value trigram index
 *   JSONB    — tags filtered with @> operator
 */

const router          = require('express').Router();
const { getPool }     = require('../db/db');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler, paginate } = require('../middleware/common');

router.use(requireAuth);
router.use(paginate);

// ── GET /api/v1/iocs ──────────────────────────────────────────────────────────
// Reads from the active_iocs view (DB Concept: Views)
router.get('/', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { limit, offset } = req.pagination;

  const { type, source_feed, malware_family, tag, since } = req.query;

  let query = db('active_iocs');

  // All filters use indexed columns
  if (type)           query = query.where('type', type);
  if (source_feed)    query = query.where('source_feed', source_feed);
  if (malware_family) query = query.where('malware_family', malware_family);
  if (since)          query = query.where('last_seen', '>=', since);

  // JSONB tag filter: WHERE tags @> '["Cobalt Strike"]'
  if (tag) {
    query = query.whereRaw('tags @> ?::jsonb', [JSON.stringify([tag])]);
  }

  const [{ count }] = await query.clone().count('id as count');
  const rows = await query
    .orderBy('last_seen', 'desc')
    .limit(limit)
    .offset(offset);

  res.json({ total: Number(count), page: req.pagination.page, limit, data: rows });
}));

// ── GET /api/v1/iocs/search ───────────────────────────────────────────────────
// Trigram similarity search on IOC value (GiST index, migration 004)
// Also supports exact match for IPs/hashes where precision matters
router.get('/search', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { q, exact } = req.query;

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Query param `q` must be at least 2 characters' });
  }

  const { limit, offset } = req.pagination;

  let rows;
  if (exact === 'true') {
    // Exact match — uses B-tree on value (fast for hash lookups)
    rows = await db('active_iocs')
      .where('value', q.trim())
      .limit(limit)
      .offset(offset);
  } else {
    // Trigram similarity — uses GiST gist_trgm_ops index
    const result = await db.raw(`
      SELECT *,
        similarity(value, ?) AS sim
      FROM active_iocs
      WHERE value % ?
         OR value ILIKE ?
      ORDER BY sim DESC, last_seen DESC
      LIMIT ? OFFSET ?
    `, [q, q, `%${q}%`, limit, offset]);
    rows = result.rows;
  }

  res.json({ query: q, exact: exact === 'true', data: rows });
}));

// ── GET /api/v1/iocs/stats ────────────────────────────────────────────────────
// Dashboard KPI data — counts grouped by type and source feed
router.get('/stats', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);

  const [byType, byFeed, recent] = await Promise.all([
    db('iocs').select('type').count('id as count').groupBy('type').orderBy('count', 'desc'),

    db('iocs').select('source_feed').count('id as count').groupBy('source_feed').orderBy('count', 'desc'),

    // IOCs added in last 24h
    db('iocs').where('created_at', '>=', db.raw("NOW() - INTERVAL '24 hours'")).count('id as count').first(),
  ]);

  res.json({
    byType,
    byFeed,
    last24h: Number(recent?.count ?? 0),
  });
}));

// ── POST /api/v1/iocs/lookup ──────────────────────────────────────────────────
// Bulk lookup: paste many indicators at once (from an alert, email, etc.) and
// get back which ones are known. Handles "defanged" indicators automatically
// (e.g. 1[.]2[.]3[.]4, hxxp://evil, evil(dot)com).
function refang(raw) {
  return String(raw)
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.\}|\(dot\)|\[dot\]/gi, '.')
    .replace(/\[@\]|\(at\)|\[at\]/gi, '@')
    .replace(/^h(?:xx|XX)?p(s?):\/\//i, 'http$1://')
    .replace(/^(\s*)/, '');
}

router.post('/lookup', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { values } = req.body;

  if (!Array.isArray(values) || values.length === 0) {
    return res.status(400).json({ error: 'Body must include a non-empty `values` array' });
  }
  if (values.length > 500) {
    return res.status(400).json({ error: 'Too many indicators — limit is 500 per request' });
  }

  // Normalise: refang, drop blanks, de-duplicate (case-insensitive).
  const inputs = [];
  const seen   = new Set();
  for (const v of values) {
    const refanged = refang(v);
    if (!refanged) continue;
    const key = refanged.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    inputs.push(refanged);
  }

  if (inputs.length === 0) {
    return res.status(400).json({ error: 'No valid indicators found in `values`' });
  }

  // Build candidate set (exact + lowercase) so hashes/domains match regardless of case.
  const candidates = new Set();
  for (const i of inputs) { candidates.add(i); candidates.add(i.toLowerCase()); }

  const matches = await db('active_iocs').whereIn('value', [...candidates]);

  // Group matches by lowercased value for quick assembly.
  const byValue = new Map();
  for (const m of matches) {
    const k = String(m.value).toLowerCase();
    if (!byValue.has(k)) byValue.set(k, []);
    byValue.get(k).push(m);
  }

  const results = inputs.map(input => ({
    input,
    matches: byValue.get(input.toLowerCase()) ?? [],
  }));

  const found = results.filter(r => r.matches.length > 0).length;

  res.json({
    summary: { total: inputs.length, found, notFound: inputs.length - found },
    results,
  });
}));

// ── GET /api/v1/iocs/:id ──────────────────────────────────────────────────────
router.get('/:id', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);

  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid IOC id' });

  const row = await db('active_iocs').where('id', id).first();
  if (!row) return res.status(404).json({ error: 'IOC not found' });

  res.json(row);
}));

module.exports = router;
