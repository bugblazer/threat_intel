/**
 * dashboard.routes.js — /api/v1/dashboard
 *
 * GET /summary  — all KPI card data + chart data in one request
 *                 (CVE count, IOC count, technique coverage, recent threats)
 *
 * This endpoint hits multiple views and aggregates in a single round-trip
 * so the dashboard doesn't need to make 5 separate requests on load.
 *
 * DB Concepts demonstrated:
 *   Views   — reads from high_severity_cves, active_iocs, technique_frequency
 *   Indexing — all sub-queries use indexed columns
 */

const router          = require('express').Router();
const { getPool }     = require('../db/db');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/common');

router.use(requireAuth);

// ── GET /api/v1/dashboard/summary ────────────────────────────────────────────
router.get('/summary', asyncHandler(async (req, res) => {
  const db = getPool(req.user.role);

  // Run all aggregations in parallel
  const [
    cveStats,
    iocStats,
    techniqueStats,
    coverageStats,
    severityDistribution,
    recentCves,
    recentIocs,
    topTechniques,
  ] = await Promise.all([
    // CVE counts by severity
    db('cves')
      .select('severity')
      .count('id as count')
      .whereNotNull('severity')
      .groupBy('severity')
      .orderBy('count', 'desc'),

    // IOC total and breakdown by type
    db('iocs')
      .select('type')
      .count('id as count')
      .groupBy('type')
      .orderBy('count', 'desc'),

    // Technique coverage
    db('techniques').count('id as total').first(),

    // Detection coverage — techniques grouped by detection_status
    db('techniques').select('detection_status').count('id as count').groupBy('detection_status'),

    // Severity donut chart data (CRITICAL/HIGH/MEDIUM/LOW)
    db.raw(`
      SELECT severity, COUNT(*) as count
      FROM cves
      WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')
      GROUP BY severity
    `),

    // 5 most recently published CVEs
    db('cves')
      .select('cve_id', 'description', 'cvss_score', 'severity', 'published_at')
      .orderBy('published_at', 'desc')
      .limit(5),

    // 10 most recent IOCs
    db('active_iocs')
      .select('value', 'type', 'source_feed', 'malware_family', 'last_seen')
      .limit(10),

    // Top 10 techniques by frequency (from view)
    db('technique_frequency')
      .select('technique_id', 'name', 'tactic', 'total_frequency', 'ioc_count', 'cve_count')
      .orderBy('total_frequency', 'desc')
      .limit(10),
  ]);

  // Compute top-level KPI numbers
  const totalCves = cveStats.reduce((sum, r) => sum + Number(r.count), 0);
  const totalIocs = iocStats.reduce((sum, r) => sum + Number(r.count), 0);
  const criticalCves = cveStats.find(r => r.severity === 'CRITICAL')?.count ?? 0;

  // Detection coverage breakdown
  const cov = Object.fromEntries((coverageStats ?? []).map(r => [r.detection_status, Number(r.count)]));
  const detectedTechniques = cov.detected ?? 0;
  const partialTechniques  = cov.partial  ?? 0;
  const blindTechniques    = cov.none     ?? 0;
  const totalTechniques    = Number(techniqueStats?.total ?? 0);
  // Partial counts as half-covered for a single headline percentage.
  const coveragePct = totalTechniques
    ? Math.round(((detectedTechniques + partialTechniques * 0.5) / totalTechniques) * 100)
    : 0;

  res.json({
    kpis: {
      totalCves,
      totalIocs,
      totalTechniques,
      criticalCves:     Number(criticalCves),
      coveragePct,
      detectedTechniques,
      partialTechniques,
      blindTechniques,
    },
    charts: {
      severityDistribution: severityDistribution.rows,
      iocsByType:           iocStats,
    },
    feeds: {
      recentCves,
      recentIocs,
      topTechniques,
    },
  });
}));

module.exports = router;
