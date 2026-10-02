/**
 * kev.js — CISA Known Exploited Vulnerabilities (KEV)
 *
 * Source:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Format:  one JSON document listing every CVE CISA has confirmed is exploited in the wild
 *
 * Two steps:
 *   1. Pull every KEV CVE from NVD (`hasKev`, about 1,700 CVEs, one page). The regular NVD
 *      sync only fetches recently modified CVEs, so most KEV entries (some date back to
 *      2002) would otherwise never be in the database at all.
 *   2. Stamp the CISA fields (date added, due date, ransomware use) onto those rows, and
 *      clear them from any CVE that has since been removed from the catalog.
 *
 * If NVD is unavailable, step 2 still runs for the CVEs we already have.
 */

const { fetchWithRetry } = require('../utils/fetchWithRetry');
const { batchUpsert }    = require('../utils/upsert');
const { makeLogger }     = require('../utils/logger');
const { parseCve, fetchPage } = require('./nvd');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_PAGE = 2000;
const NVD_GAP_MS = process.env.NVD_API_KEY ? 650 : 6500;
const sleep = ms => new Promise(r => setTimeout(r, ms));

/** Map one catalog entry to the columns we store. Exported for tests. */
function parseKevEntry(v) {
  if (!/^CVE-\d{4}-\d{4,}$/.test(v?.cveID ?? '')) return null;
  return {
    cve_id:         v.cveID,
    kev_added_at:   v.dateAdded || null,
    kev_due_date:   v.dueDate || null,
    kev_ransomware: String(v.knownRansomwareCampaignUse).toLowerCase() === 'known',
  };
}

async function fetchKevCatalog() {
  const res  = await fetchWithRetry(KEV_URL, { timeoutMs: 60_000, retries: 3 });
  const data = await res.json();
  return (data.vulnerabilities ?? []).map(parseKevEntry).filter(Boolean);
}

/** Upsert full NVD records for every CVE in KEV. Returns how many were fetched. */
async function syncKevCvesFromNvd(db, log) {
  const params = new URLSearchParams({ resultsPerPage: NVD_PAGE, startIndex: 0 });
  let fetched = 0;
  let total = Infinity;

  for (let start = 0; start < total; start += NVD_PAGE) {
    if (start > 0) await sleep(NVD_GAP_MS);
    params.set('startIndex', start);
    const page = await fetchPage(params, { extraQuery: '&hasKev' });
    total = page.totalResults ?? 0;
    const rows = (page.vulnerabilities ?? []).map(parseCve);
    await batchUpsert(db, 'cves', rows, ['cve_id'], log);
    fetched += rows.length;
  }
  return fetched;
}

async function ingestKev(db) {
  const log = makeLogger('KEV');

  let nvdFetched = 0;
  try {
    nvdFetched = await syncKevCvesFromNvd(db, log);
    log.info(`NVD: upserted ${nvdFetched} KEV CVEs`);
  } catch (err) {
    log.warn(`NVD hasKev fetch failed, flagging existing CVEs only: ${err.message}`);
  }

  const catalog = await fetchKevCatalog();
  log.info(`CISA catalog: ${catalog.length} entries`);

  let flagged = 0;
  await db.transaction(async (trx) => {
    // Clear everything first so CVEs removed from the catalog lose the flag,
    // then set the current entries in batches with an UPDATE ... FROM (VALUES ...).
    await trx('cves').whereNotNull('kev_added_at').update({ kev_added_at: null, kev_due_date: null, kev_ransomware: false });

    for (let i = 0; i < catalog.length; i += 500) {
      const chunk = catalog.slice(i, i + 500);
      const values = chunk.map(() => '(?, ?::date, ?::date, ?::boolean)').join(', ');
      const bindings = chunk.flatMap(k => [k.cve_id, k.kev_added_at, k.kev_due_date, k.kev_ransomware]);
      const result = await trx.raw(`
        UPDATE cves AS c
           SET kev_added_at = v.added, kev_due_date = v.due, kev_ransomware = v.ransomware
          FROM (VALUES ${values}) AS v(cve_id, added, due, ransomware)
         WHERE c.cve_id = v.cve_id
      `, bindings);
      flagged += result.rowCount ?? 0;
    }
  });

  log.done(`KEV complete: ${flagged} of ${catalog.length} catalog CVEs flagged`);
  return { catalog: catalog.length, nvdFetched, flagged };
}

module.exports = { ingestKev, parseKevEntry };
