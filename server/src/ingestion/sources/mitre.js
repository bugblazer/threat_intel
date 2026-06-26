/**
 * mitre.js — MITRE ATT&CK Ingestion
 *
 * Source:  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
 * Format:  STIX 2.1 bundle (single large JSON file, ~10 MB)
 * Schedule: Weekly (data changes infrequently)
 *
 * What it ingests:
 *   - attack-pattern objects → `techniques` table
 *   - Extracts: technique_id (T####.###), name, tactic, description,
 *     platforms, kill_chain_phases, external_refs, is_subtechnique
 *
 * DB concepts exercised:
 *   - JSONB: platforms and kill_chain_phases stored as JSONB
 *   - Upsert: re-running never creates duplicates (ON CONFLICT technique_id)
 */

const { fetchWithRetry }  = require('../utils/fetchWithRetry');
const { batchUpsert }     = require('../utils/upsert');
const { makeLogger }      = require('../utils/logger');

const STIX_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

/**
 * Parse a STIX attack-pattern object into a `techniques` table row.
 * Returns null for objects that aren't usable techniques.
 */
function parseTechnique(obj) {
  if (obj.type !== 'attack-pattern') return null;
  if (obj.revoked || obj.x_mitre_deprecated) return null;

  // Extract the T#### or T####.### ID from external_references
  const mitreRef = (obj.external_references || []).find(
    r => r.source_name === 'mitre-attack',
  );
  if (!mitreRef?.external_id) return null;

  const techniqueId = mitreRef.external_id; // e.g. "T1059" or "T1059.001"
  const isSubtechnique = techniqueId.includes('.');
  const parentId = isSubtechnique ? techniqueId.split('.')[0] : null;

  // Primary tactic (first kill chain phase, mitre-attack chain)
  const mitrePhases = (obj.kill_chain_phases || []).filter(
    p => p.kill_chain_name === 'mitre-attack',
  );
  const tactic = mitrePhases[0]?.phase_name ?? null;

  return {
    technique_id:       techniqueId,
    name:               obj.name,
    tactic,
    description:        obj.description ?? null,
    platforms:          JSON.stringify(obj.x_mitre_platforms ?? []),
    kill_chain_phases:  JSON.stringify(mitrePhases),
    external_refs:      JSON.stringify(obj.external_references ?? []),
    is_subtechnique:    isSubtechnique,
    parent_technique_id: parentId,
    updated_at:         new Date(),
  };
}

/**
 * Main ingestion function.
 * @param {import('knex').Knex} db - contributor pool
 */
async function ingestMitre(db) {
  const log = makeLogger('MITRE');
  log.info('Starting MITRE ATT&CK ingestion…');

  // 1. Fetch STIX bundle
  log.info(`Fetching STIX bundle from ${STIX_URL}`);
  const res  = await fetchWithRetry(STIX_URL, { timeoutMs: 60_000 });
  const bundle = await res.json();

  const objects = bundle.objects ?? [];
  log.info(`Bundle contains ${objects.length} STIX objects`);

  // 2. Parse attack-pattern objects into table rows
  const rows = objects
    .map(parseTechnique)
    .filter(Boolean);

  log.info(`Parsed ${rows.length} techniques (excluding revoked/deprecated)`);

  // 3. Upsert into techniques table
  await batchUpsert(db, 'techniques', rows, ['technique_id'], log);

  log.done(`MITRE ingestion complete — ${rows.length} techniques upserted`);
  return { count: rows.length };
}

module.exports = { ingestMitre };
