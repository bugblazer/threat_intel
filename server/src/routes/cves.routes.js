/**
 * cves.routes.js — /api/v1/cves
 *
 * GET  /             — paginated list with filters (severity, score range, date)
 * GET  /search       — full-text search using tsvector (DB Concept: Full-Text Search)
 * GET  /high-severity — read from high_severity_cves view (DB Concept: Views)
 * GET  /:cveId       — single CVE detail with linked techniques
 *
 * All endpoints use the readonly pool — analysts never need to write here.
 *
 * DB Concepts demonstrated:
 *   Full-Text Search — tsvector @@ plainto_tsquery with ts_rank ordering
 *   Views            — high_severity_cves view backed by indexed JOIN
 *   Indexing         — cvss_score, severity, published_at, cve_id indexes used
 */

const router           = require('express').Router();
const { getPool }      = require('../db/db');
const { requireAuth }  = require('../middleware/auth');
const { asyncHandler, paginate } = require('../middleware/common');

router.use(requireAuth);
router.use(paginate);

// ── GET /api/v1/cves ─────────────────────────────────────────────────────────
router.get('/', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { limit, offset } = req.pagination;

  const {
    severity,          // CRITICAL|HIGH|MEDIUM|LOW
    min_score,         // e.g. 7.0
    max_score,         // e.g. 10.0
    cwe_id,
    published_after,   // ISO date string
    published_before,
    sort,              // 'severity' (default) | 'threat' | 'recent'
    threat_only,       // 'true' — only CVEs linked to a technique or IOC
  } = req.query;

  // "Threat signal" sub-selects: how many ATT&CK techniques this CVE maps to,
  // and how many known IOCs reference it. Powers threat-informed prioritisation.
  const TECH_EXPR = '(SELECT COUNT(*) FROM cve_technique_map ctm WHERE ctm.cve_id = c.id)';
  const IOC_EXPR  = '(SELECT COUNT(*) FROM iocs i WHERE i.linked_cve_id = c.id)';

  let query = db('cves as c');

  // Apply filters — each uses a dedicated index (migration 004)
  if (severity)         query = query.where('c.severity', severity.toUpperCase());
  if (min_score)        query = query.where('c.cvss_score', '>=', parseFloat(min_score));
  if (max_score)        query = query.where('c.cvss_score', '<=', parseFloat(max_score));
  if (cwe_id)           query = query.where('c.cwe_id', cwe_id);
  if (published_after)  query = query.where('c.published_at', '>=', published_after);
  if (published_before) query = query.where('c.published_at', '<=', published_before);

  // Only vulnerabilities with real-world threat context attached.
  if (threat_only === 'true') {
    query = query.where(function () {
      this.whereExists(function () {
        this.select(db.raw('1')).from('cve_technique_map as ctm').whereRaw('ctm.cve_id = c.id');
      }).orWhereExists(function () {
        this.select(db.raw('1')).from('iocs as i').whereRaw('i.linked_cve_id = c.id');
      });
    });
  }

  // Count matching rows (filters only — sub-selects don't affect the count)
  const [{ count }] = await query.clone().count('* as count');

  // Fetch matching rows, decorated with the threat signal.
  let rowsQuery = query.clone().select(
    'c.id',
    'c.cve_id',
    'c.description',
    'c.cvss_score',
    'c.severity',
    'c.cwe_id',
    'c.published_at',
    'c.affected_products',
    db.raw(`${TECH_EXPR}::int AS technique_count`),
    db.raw(`${IOC_EXPR}::int  AS ioc_count`),
    db.raw(`(${TECH_EXPR} + ${IOC_EXPR})::int AS threat_score`),
  );

  if (sort === 'threat') {
    rowsQuery = rowsQuery
      .orderByRaw(`(${TECH_EXPR} + ${IOC_EXPR}) DESC`)
      .orderBy('c.cvss_score', 'desc');
  } else if (sort === 'recent') {
    rowsQuery = rowsQuery.orderBy('c.published_at', 'desc');
  } else {
    rowsQuery = rowsQuery.orderBy('c.cvss_score', 'desc').orderBy('c.published_at', 'desc');
  }

  const rows = await rowsQuery.limit(limit).offset(offset);

  res.json({
    total: Number(count),
    page:  req.pagination.page,
    limit,
    data:  rows,
  });
}));

// ── GET /api/v1/cves/search ───────────────────────────────────────────────────
// DB Concept: Full-Text Search
// Uses the tsvector column populated by the trigger in migration 005.
router.get('/search', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { q } = req.query;

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Query param `q` must be at least 2 characters' });
  }

  const { limit, offset } = req.pagination;

  // plainto_tsquery converts free text to a tsquery (handles spaces, special chars safely)
  // ts_rank scores matches by how well they match the query
  const rows = await db.raw(`
    SELECT
      id,
      cve_id,
      description,
      cvss_score,
      severity,
      cwe_id,
      published_at,
      ts_rank(search_vector, plainto_tsquery('english', ?)) AS rank
    FROM cves
    WHERE search_vector @@ plainto_tsquery('english', ?)
    ORDER BY rank DESC, cvss_score DESC
    LIMIT ? OFFSET ?
  `, [q, q, limit, offset]);

  const countResult = await db.raw(`
    SELECT COUNT(*) as count
    FROM cves
    WHERE search_vector @@ plainto_tsquery('english', ?)
  `, [q]);

  res.json({
    total: Number(countResult.rows[0].count),
    page:  req.pagination.page,
    limit,
    query: q,
    data:  rows.rows,
  });
}));

// ── GET /api/v1/cves/high-severity ────────────────────────────────────────────
// DB Concept: Views — reads directly from the high_severity_cves view
router.get('/high-severity', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);
  const { limit, offset } = req.pagination;

  const rows = await db('high_severity_cves')
    .limit(limit)
    .offset(offset);

  const [{ count }] = await db('high_severity_cves').count('id as count');

  res.json({
    total: Number(count),
    page:  req.pagination.page,
    limit,
    data:  rows,
  });
}));

// ── GET /api/v1/cves/:cveId ───────────────────────────────────────────────────
router.get('/:cveId', asyncHandler(async (req, res) => {
  const db  = getPool(req.user.role);
  const cve = await db('cves').where({ cve_id: req.params.cveId.toUpperCase() }).first();

  if (!cve) return res.status(404).json({ error: 'CVE not found' });

  // Fetch linked techniques via join table
  const techniques = await db('cve_technique_map as ctm')
    .join('techniques as t', 't.id', 'ctm.technique_id')
    .where('ctm.cve_id', cve.id)
    .select('t.technique_id', 't.name', 't.tactic', 't.platforms', 'ctm.confidence_score');

  res.json({ ...cve, techniques });
}));

module.exports = router;
