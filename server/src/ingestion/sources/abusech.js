/**
 * abusech.js — Abuse.ch Feed Ingestion
 *
 * Three sub-feeds from abuse.ch, all public (no API key):
 *
 *   MalwareBazaar  — malware sample hashes (MD5/SHA256/SHA1)
 *     POST https://mb-api.abuse.ch/api/v1/  { query: "get_recent", selector: "time" }
 *
 *   URLhaus        — malicious URLs used to distribute malware
 *     GET  https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/
 *
 *   ThreatFox      — C2 indicators (IPs/domains/URLs)
 *     POST https://threatfox-api.abuse.ch/api/v1/  { query: "get_iocs", days: 1 }
 *
 * All three write to the `iocs` table with their source_feed tagged.
 * Unique key: (value, source_feed) — defined in migration 002.
 *
 * DB concepts exercised:
 *   - Upsert: ON CONFLICT (value, source_feed) DO UPDATE
 *   - JSONB: tags and meta columns
 *   - Indexing: type, source_feed, last_seen, malware_family, value trigram
 */

const { fetchWithRetry } = require('../utils/fetchWithRetry');
const { batchUpsert }    = require('../utils/upsert');
const { makeLogger }     = require('../utils/logger');

const MALWARE_BAZAAR_URL = 'https://mb-api.abuse.ch/api/v1/';
const URLHAUS_URL        = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/';
const THREATFOX_URL      = 'https://threatfox-api.abuse.ch/api/v1/';

function abuseHeaders(contentType = 'application/json') {
  const headers = {
    'User-Agent': 'ThreatIntel/1.0',
    'Content-Type': contentType,
  };

  if (process.env.ABUSECH_AUTH_KEY) {
    headers['Auth-Key'] = process.env.ABUSECH_AUTH_KEY;
  }

  return headers;
}

function deduplicateIocs(rows) {
  const unique = new Map();

  for (const row of rows) {
    unique.set(`${row.value}:${row.source_feed}`, row);
  }

  return [...unique.values()];
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────────

async function fetchMalwareBazaar() {
  // MalwareBazaar uses POST with a form body — node-fetch needs method override
  // We re-fetch here because fetchWithRetry uses GET by default
  const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
  const postRes = await fetch(MALWARE_BAZAAR_URL, {
    method: 'POST',
    headers: abuseHeaders('application/x-www-form-urlencoded'),
    body: 'query=get_recent&selector=time',
  });
  const data = await postRes.json();
  return data.data ?? [];
}

function parseMalwareBazaar(sample) {
  const now = new Date();
  return {
    value:          sample.sha256_hash,
    type:           'sha256',
    source_feed:    'malwarebazaar',
    first_seen:     sample.first_seen ? new Date(sample.first_seen) : now,
    last_seen:      now,
    malware_family: sample.signature ?? sample.tags?.[0] ?? null,
    threat_type:    'malware',
    confidence:     90,
    tags:           JSON.stringify(sample.tags ?? []),
    meta:           JSON.stringify({
      file_name: sample.file_name,
      file_type: sample.file_type,
      file_size: sample.file_size,
      md5:       sample.md5_hash,
      sha1:      sample.sha1_hash,
      reporter:  sample.reporter,
    }),
    updated_at: now,
  };
}

// ── URLhaus ───────────────────────────────────────────────────────────────────

async function fetchUrlhaus() {
  const res  = await fetchWithRetry(URLHAUS_URL, { 
    headers: abuseHeaders(),
    timeoutMs: 30_000 
  });
  const data = await res.json();
  return data.urls ?? [];
}

function parseUrlhaus(entry) {
  const now = new Date();
  return {
    value:          entry.url,
    type:           'url',
    source_feed:    'urlhaus',
    first_seen:     entry.date_added ? new Date(entry.date_added) : now,
    last_seen:      now,
    malware_family: entry.tags?.[0]  ?? null,
    threat_type:    'payload_delivery',
    confidence:     80,
    tags:           JSON.stringify(entry.tags ?? []),
    meta:           JSON.stringify({
      url_status: entry.url_status,
      host:       entry.host,
      reporter:   entry.reporter,
    }),
    updated_at: now,
  };
}

// ── ThreatFox ─────────────────────────────────────────────────────────────────

async function fetchThreatFox(daysBack = 1) {
  const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
  const res = await fetch(THREATFOX_URL, {
    method:  'POST',
    headers: abuseHeaders(),
    body:    JSON.stringify({ query: 'get_iocs', days: daysBack }),
  });
  const data = await res.json();
  return data.data ?? []; 
}

function parseThreatFox(ioc) {
  const now = new Date();

  // Normalise IOC type to our internal vocabulary
  const typeMap = {
    'ip:port': 'ip',
    'domain':  'domain',
    'url':     'url',
    'md5_hash':    'md5',
    'sha256_hash': 'sha256',
  };
  const type = typeMap[ioc.ioc_type] ?? ioc.ioc_type ?? 'unknown';

  // Strip port from IP:port values so we store the raw IP
  let value = ioc.ioc;
  if (ioc.ioc_type === 'ip:port' && value.includes(':')) {
    value = value.split(':')[0];
  }

  return {
    value,
    type,
    source_feed:    'threatfox',
    first_seen:     ioc.first_seen ? new Date(ioc.first_seen) : now,
    last_seen:      ioc.last_seen  ? new Date(ioc.last_seen)  : now,
    malware_family: ioc.malware    ?? null,
    threat_type:    ioc.threat_type ?? 'botnet_cc',
    confidence:     ioc.confidence_level ?? 50,
    tags:           JSON.stringify(ioc.tags ?? []),
    meta:           JSON.stringify({
      ioc_type_desc: ioc.ioc_type_desc,
      reporter:      ioc.reporter,
      reference:     ioc.reference,
    }),
    updated_at: now,
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────

/**
 * @param {import('knex').Knex} db - contributor pool
 */
async function ingestAbusech(db) {
  const log = makeLogger('ABUSE.CH');
  log.info('Starting Abuse.ch ingestion (MalwareBazaar + URLhaus + ThreatFox)…');

  let totalCount = 0;

  // ── MalwareBazaar ────────────────────────────────────────────────────────
  try {
    log.info('Fetching MalwareBazaar recent samples…');
    const samples = await fetchMalwareBazaar();
    const rows = deduplicateIocs(samples.map(parseMalwareBazaar));
    await batchUpsert(db, 'iocs', rows, ['value', 'source_feed'], log);
    totalCount += rows.length;
    log.done(`MalwareBazaar: ${rows.length} hashes upserted`);
  } catch (err) {
    log.error('MalwareBazaar failed:', err.message);
  }

  // ── URLhaus ──────────────────────────────────────────────────────────────
  try {
    log.info('Fetching URLhaus recent URLs…');
    const entries = await fetchUrlhaus();
    const rows = deduplicateIocs(entries.map(parseUrlhaus));
    await batchUpsert(db, 'iocs', rows, ['value', 'source_feed'], log);
    totalCount += rows.length;
    log.done(`URLhaus: ${rows.length} URLs upserted`);
  } catch (err) {
    log.error('URLhaus failed:', err.message);
  }

  // ── ThreatFox ────────────────────────────────────────────────────────────
  try {
    log.info('Fetching ThreatFox IOCs (last 24h)…');
    const iocs = await fetchThreatFox(1);
    const rows = deduplicateIocs(iocs.map(parseThreatFox));
    await batchUpsert(db, 'iocs', rows, ['value', 'source_feed'], log);
    totalCount += rows.length;
    log.done(`ThreatFox: ${rows.length} IOCs upserted`);
  } catch (err) {
    log.error('ThreatFox failed:', err.message);
  }

  log.done(`Abuse.ch ingestion complete — ${totalCount} total IOCs upserted`);
  return { count: totalCount };
}

module.exports = { ingestAbusech };
