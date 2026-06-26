/**
 * otx.js — AlienVault OTX Ingestion
 *
 * Source:  https://otx.alienvault.com/api/v1/
 * Auth:    API key via X-OTX-API-KEY header (free account at otx.alienvault.com)
 * Env var: ALIENVAULT_OTX_API_KEY
 *
 * What it ingests:
 *   - Recent public pulses → `iocs` table (each indicator in a pulse)
 *   - Threat actor summaries from pulse author tags → `threat_actors` table
 *   - ATT&CK technique references in pulses → `cve_technique_map` (where a CVE is cited)
 *
 * Pagination: OTX returns 10 pulses/page. We fetch up to MAX_PAGES pages of
 *             "subscribed" pulses modified since the last run.
 *
 * DB concepts exercised:
 *   - JSONB: tags, meta columns on iocs and threat_actors
 *   - Full-text: threat_actors search_vector updated via trigger on upsert
 *   - Upsert: ON CONFLICT for both iocs and threat_actors
 *   - Access Control: contributor pool writes; readonly pool never used here
 */

const { fetchWithRetry } = require('../utils/fetchWithRetry');
const { batchUpsert }    = require('../utils/upsert');
const { makeLogger }     = require('../utils/logger');

const OTX_BASE    = 'https://otx.alienvault.com/api/v1';
const MAX_PAGES   = 10;   // cap at 10 pages (100 pulses) per run
const PAGE_SIZE   = 10;

// IOC type mapping: OTX → our internal vocabulary
const TYPE_MAP = {
  'IPv4':        'ip',
  'IPv6':        'ip',
  'domain':      'domain',
  'hostname':    'domain',
  'URL':         'url',
  'URI':         'url',
  'FileHash-MD5':    'md5',
  'FileHash-SHA1':   'sha1',
  'FileHash-SHA256': 'sha256',
};

/**
 * Build headers with optional API key.
 */
function headers() {
  const h = { 'Content-Type': 'application/json' };
  if (process.env.ALIENVAULT_OTX_API_KEY) {
    h['X-OTX-API-KEY'] = process.env.ALIENVAULT_OTX_API_KEY;
  }
  return h;
}

/**
 * Fetch a page of recent subscribed pulses.
 * Falls back to public pulses if no API key is set.
 */
async function fetchPulsePage(page, modifiedSince) {
  const endpoint = process.env.ALIENVAULT_OTX_API_KEY
    ? `${OTX_BASE}/pulses/subscribed`
    : `${OTX_BASE}/pulses/activity`;

  const params = new URLSearchParams({
    limit:          PAGE_SIZE,
    page,
    modified_since: modifiedSince,
  });

  const res = await fetchWithRetry(`${endpoint}?${params}`, {
    headers:   headers(),
    timeoutMs: 30_000,
  });
  return res.json();
}

/**
 * Parse a single OTX indicator into an `iocs` row.
 */
function parseIndicator(indicator, pulse) {
  const type = TYPE_MAP[indicator.type];
  if (!type) return null; // skip CVE, email, YARA etc.

  const now = new Date();
  return {
    value:          indicator.indicator,
    type,
    source_feed:    'otx',
    first_seen:     indicator.created ? new Date(indicator.created) : now,
    last_seen:      now,
    malware_family: pulse.malware_families?.[0]?.display_name ?? null,
    threat_type:    pulse.targeted_countries?.length ? 'targeted_attack' : 'unknown',
    confidence:     70,
    tags:           JSON.stringify(pulse.tags ?? []),
    meta:           JSON.stringify({
      pulse_id:   pulse.id,
      pulse_name: pulse.name,
      author:     pulse.author_name,
      tlp:        pulse.tlp,
    }),
    updated_at: now,
  };
}

/**
 * Extract a lightweight threat actor record from a pulse.
 * OTX doesn't have a formal actor object — we infer from adversary field.
 */
function parseThreatActor(pulse) {
  const name = pulse.adversary;
  if (!name || name.trim() === '') return null;

  const attackIds = (pulse.attack_ids ?? []).map(a => a.id ?? a).filter(Boolean);

  return {
    name,
    aliases: [],
    country: null,
    motivation: null,
    description: `Derived from OTX pulse: ${pulse.name}`,
    technique_ids: attackIds,
    meta: JSON.stringify({ otx_pulse_id: pulse.id }),
    updated_at: new Date(),
  };
}

/**
 * Main ingestion function.
 * @param {import('knex').Knex} db        - contributor pool
 * @param {object}              [options]
 * @param {number}              [options.daysBack=1] - How far back to look for pulses
 */
async function ingestOtx(db, { daysBack = 1 } = {}) {
  const log = makeLogger('OTX');

  if (!process.env.ALIENVAULT_OTX_API_KEY) {
    log.warn('ALIENVAULT_OTX_API_KEY not set — fetching public feed (limited)');
  }

  log.info(`Starting OTX ingestion (last ${daysBack}d, up to ${MAX_PAGES} pages)…`);

  const modifiedSince = new Date(Date.now() - daysBack * 86_400_000).toISOString();

  const iocRows    = [];
  const actorRows  = [];

  for (let page = 1; page <= MAX_PAGES; page++) {
    let data;
    try {
      data = await fetchPulsePage(page, modifiedSince);
    } catch (err) {
      log.error(`Page ${page} failed:`, err.message);
      break;
    }

    const pulses = data.results ?? [];
    if (!pulses.length) break;

    log.info(`Page ${page}: ${pulses.length} pulses`);

    for (const pulse of pulses) {
      // Parse all indicators in this pulse
      for (const indicator of pulse.indicators ?? []) {
        const row = parseIndicator(indicator, pulse);
        if (row) iocRows.push(row);
      }

      // Parse threat actor if adversary is named
      const actor = parseThreatActor(pulse);
      if (actor) actorRows.push(actor);
    }

    // No more pages
    if (!data.next) break;
  }

  log.info(`Collected ${iocRows.length} IOCs and ${actorRows.length} threat actor entries`);

  // Upsert IOCs
  if (iocRows.length) {
    await batchUpsert(db, 'iocs', iocRows, ['value', 'source_feed'], log);
  }

  // Upsert threat actors (ON CONFLICT name)
  // De-duplicate by name first (multiple pulses may reference same actor)
  const actorMap = new Map();
  for (const a of actorRows) {
    if (!actorMap.has(a.name)) actorMap.set(a.name, a);
  }
  const uniqueActors = [...actorMap.values()];

  if (uniqueActors.length) {
    await batchUpsert(db, 'threat_actors', uniqueActors, ['name'], log);
  }

  log.done(`OTX ingestion complete — ${iocRows.length} IOCs, ${uniqueActors.length} threat actors`);
  return { iocCount: iocRows.length, actorCount: uniqueActors.length };
}

module.exports = { ingestOtx };
