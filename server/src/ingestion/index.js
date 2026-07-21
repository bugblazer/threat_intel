/**
 * index.js — Ingestion Orchestrator
 *
 * Runs all four ingestion sources in sequence and reports results.
 * Can be invoked:
 *   - Manually:   node src/ingestion/index.js [--full-sync] [--source=mitre]
 *   - Via npm:    npm run ingest --workspace=server
 *   - On a cron:  imported by the Express server and scheduled via node-cron
 *
 * Flags:
 *   --full-sync        Force a full NVD sync (slow — fetches all CVEs)
 *   --source=<name>    Run only one source: mitre | nvd | abusech | otx
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });

const { pools }        = require('../db/db');
const { ingestMitre }  = require('./sources/mitre');
const { ingestNvd }    = require('./sources/nvd');
const { ingestAbusech} = require('./sources/abusech');
const { ingestOtx }    = require('./sources/otx');
const { linkAll }      = require('./sources/linker');
const { makeLogger }   = require('./utils/logger');

const log = makeLogger('ORCHESTRATOR');

// Use contributor pool for all writes
const db = pools.contributor;

/**
 * Run all ingestion sources and collect results.
 *
 * @param {object} [options]
 * @param {boolean} [options.fullSync=false]  - Force full NVD sync
 * @param {string}  [options.source]          - Run only this source
 */
async function runIngestion({ fullSync = false, source } = {}) {
  const results = {};
  const errors  = {};
  const start   = Date.now();

  log.info('═══════════════════════════════════════════════');
  log.info('Threat Intel Ingestion Run Starting');
  log.info(`Mode: ${fullSync ? 'FULL SYNC' : 'INCREMENTAL'}`);
  if (source) log.info(`Source filter: ${source}`);
  log.info('═══════════════════════════════════════════════');

  const run = async (name, fn, force = false) => {
    if (!force && source && source !== name) return;
    log.info(`\n▶  Starting ${name}…`);
    const t0 = Date.now();
    try {
      results[name] = await fn();
      log.done(`${name} finished in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    } catch (err) {
      errors[name] = err.message;
      log.error(`${name} failed: ${err.message}`);
    }
  };

  // Run sources in order — MITRE first (techniques needed for FK resolution)
  await run('mitre',   () => ingestMitre(db));
  await run('nvd',     () => ingestNvd(db, { fullSync }));
  await run('abusech', () => ingestAbusech(db));
  await run('otx',     () => ingestOtx(db));

  // Always run the linker after sources complete, unless a single specific
  // source was requested (in which case the user is testing that source alone).
  // The linker populates cve_technique_map and iocs.linked_technique_id,
  // which is what makes the ATT&CK heatmap frequency counts non-zero.
  // Run whenever data sources ran (fresh CVEs/IOCs need linking) or when
  // explicitly requested. Previously a single-source run (e.g. from the Admin
  // UI) skipped linking entirely, leaving the ATT&CK heatmap stale.
  if (source !== 'mitre') {
    await run('linker', () => linkAll(db), true);
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  log.info('\n═══════════════════════════════════════════════');
  log.info(`Ingestion complete in ${elapsed}s`);
  log.info('Results:', JSON.stringify(results, null, 2));
  if (Object.keys(errors).length) {
    log.warn('Errors:', JSON.stringify(errors, null, 2));
  }
  log.info('═══════════════════════════════════════════════\n');

  return { results, errors, elapsed };
}

// ── CLI entry point ───────────────────────────────────────────────────────────
if (require.main === module) {
  const args      = process.argv.slice(2);
  const fullSync  = args.includes('--full-sync');
  const sourceArg = args.find(a => a.startsWith('--source='));
  const source    = sourceArg ? sourceArg.split('=')[1] : undefined;

  runIngestion({ fullSync, source })
    .then(() => process.exit(0))
    .catch(err => {
      log.error('Fatal orchestrator error:', err);
      process.exit(1);
    });
}

module.exports = { runIngestion };