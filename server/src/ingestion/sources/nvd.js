/**
 * nvd.js — NVD CVE Feed Ingestion (NIST)
 *
 * Source:  https://services.nvd.nist.gov/rest/json/cves/2.0
 * Format:  JSON API, paginated (resultsPerPage max 2000)
 * Schedule: Every 6 hours (NVD updates continuously)
 *
 * Strategy:
 *   - On first run: fetch ALL CVEs (this will take several minutes — NVD is large)
 *   - On subsequent runs: fetch only CVEs modified in the last 8 hours
 *     using the `lastModStartDate` / `lastModEndDate` parameters
 *   - Rate limit: NVD asks for ≥ 6 seconds between requests without an API key.
 *     We sleep 6s between pages to be a good citizen.
 *
 * DB concepts exercised:
 *   - JSONB: affected_products and references stored as JSONB
 *   - Full-text: search_vector updated automatically by trigger on insert/update
 *   - Indexing: cve_id, cvss_score, severity, published_at all indexed
 */

const { fetchWithRetry } = require('../utils/fetchWithRetry');
const { batchUpsert }    = require('../utils/upsert');
const { makeLogger }     = require('../utils/logger');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 2000;
const RATE_LIMIT_MS = 600; // NVD asks for 6s between requests (no API key) so change it to 6500 if you're not using the key

/**
 * Map a raw NVD CVE item to a `cves` table row.
 */
function parseCve(item) {
  const cve = item.cve;
  const id  = cve.id; // "CVE-2024-12345"

  // Description (prefer English)
  const descObj = (cve.descriptions ?? []).find(d => d.lang === 'en');
  const description = descObj?.value ?? null;

  // CVSS — try v3.1, v3.0, v2.0 in order
  let cvssScore   = null;
  let cvssVersion = null;
  let cvssVector  = null;
  let severity    = null;

  const metrics = cve.metrics ?? {};
  const v31 = metrics.cvssMetricV31?.[0];
  const v30 = metrics.cvssMetricV30?.[0];
  const v2  = metrics.cvssMetricV2?.[0];
  const best = v31 ?? v30 ?? v2;

  if (best) {
    cvssScore   = best.cvssData?.baseScore ?? null;
    cvssVersion = best.cvssData?.version   ?? null;
    cvssVector  = best.cvssData?.vectorString ?? null;
    severity    = best.cvssData?.baseSeverity
               ?? best.baseSeverity
               ?? null;
  }

  // CWE
  const cweEntry = cve.weaknesses?.[0]?.description?.find(d => d.lang === 'en');
  const cweId = cweEntry?.value ?? null;

  // Affected products (CPE matches)
  const affectedProducts = [];
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        // CPE URI: cpe:2.3:a:vendor:product:version:...
        const parts = match.criteria?.split(':') ?? [];
        affectedProducts.push({
          vendor:   parts[3] ?? null,
          product:  parts[4] ?? null,
          version:  parts[5] ?? null,
          vulnerable: match.vulnerable ?? true,
        });
      }
    }
  }

  // References
  const references = (cve.references ?? []).map(r => ({
    url:  r.url,
    tags: r.tags ?? [],
  }));

  return {
    cve_id:            id,
    description,
    cvss_score:        cvssScore,
    cvss_version:      cvssVersion,
    cvss_vector:       cvssVector,
    severity:          severity ? severity.toUpperCase() : null,
    cwe_id:            cweId,
    affected_products: JSON.stringify(affectedProducts),
    references:        JSON.stringify(references),
    published_at:      cve.published    ? new Date(cve.published)    : null,
    modified_at:       cve.lastModified ? new Date(cve.lastModified) : null,
    updated_at:        new Date(),
  };
}

/**
 * Sleep helper for rate limiting.
 */
const sleep = ms => new Promise(r => setTimeout(r, ms));

/**
 * Fetch one page from the NVD API.
 * @param {URLSearchParams} params
 */
async function fetchPage(params) {
  const headers = {};
  if (process.env.NVD_API_KEY) {
    headers['apiKey'] = process.env.NVD_API_KEY;
  }
  const url = `${NVD_BASE}?${params.toString()}`;
  const res  = await fetchWithRetry(url, { timeoutMs: 60_000, retries: 3 });
  return res.json();
}

/**
 * Main ingestion function.
 *
 * @param {import('knex').Knex} db        - contributor pool
 * @param {object}              [options]
 * @param {boolean}             [options.fullSync=false]  - Fetch all CVEs (slow, first run)
 * @param {number}              [options.hoursBack=8]     - Hours to look back for updates
 */
async function ingestNvd(db, { fullSync = false, hoursBack = 8 } = {}) {
  const log = makeLogger('NVD');
  log.info(`Starting NVD ingestion (${fullSync ? 'FULL SYNC' : `last ${hoursBack}h`})…`);

  const params = new URLSearchParams({ resultsPerPage: PAGE_SIZE, startIndex: 0 });

  if (!fullSync) {
    const now   = new Date();
    const start = new Date(now - hoursBack * 60 * 60 * 1000);
    params.set('lastModStartDate', start.toISOString());
    params.set('lastModEndDate',   now.toISOString());
  }

  // First page — tells us total results
  log.info('Fetching first page…');
  const firstPage = await fetchPage(params);
  const total     = firstPage.totalResults ?? 0;

  log.info(`Total CVEs to fetch: ${total}`);

  let allRows = (firstPage.vulnerabilities ?? []).map(parseCve);

  // Paginate through remaining pages
  const totalPages = Math.ceil(total / PAGE_SIZE);
  for (let page = 1; page < totalPages; page++) {
    await sleep(RATE_LIMIT_MS);
    params.set('startIndex', page * PAGE_SIZE);
    log.info(`Fetching page ${page + 1}/${totalPages}…`);
    const data = await fetchPage(params);
    allRows = allRows.concat((data.vulnerabilities ?? []).map(parseCve));
  }

  log.info(`Parsed ${allRows.length} CVEs — upserting…`);
  await batchUpsert(db, 'cves', allRows, ['cve_id'], log);

  log.done(`NVD ingestion complete — ${allRows.length} CVEs upserted`);
  return { count: allRows.length };
}

module.exports = { ingestNvd };
