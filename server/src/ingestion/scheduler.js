/**
 * scheduler.js — Ingestion Cron Scheduler
 *
 * Imported by the Express server (src/index.js) to kick off periodic ingestion.
 * Uses node-cron. Schedule is configurable via INGEST_CRON env var.
 *
 * Default schedule: every 6 hours ("0 *\/6 * * *")
 * MITRE re-sync:    every Sunday at midnight (data changes rarely)
 *
 * Usage in server:
 *   const { startScheduler } = require('./ingestion/scheduler');
 *   startScheduler();
 */

const cron            = require('node-cron');
const { runIngestion} = require('./index');
const { makeLogger }  = require('./utils/logger');

const log = makeLogger('SCHEDULER');

function startScheduler() {
  // ── Incremental sync — every 6 hours ────────────────────────────────────
  const incrementalCron = process.env.INGEST_CRON || '0 */6 * * *';

  cron.schedule(incrementalCron, async () => {
    log.info(`Cron triggered (${incrementalCron}) — running incremental ingestion`);
    try {
      await runIngestion({ fullSync: false });
    } catch (err) {
      log.error('Scheduled ingestion failed:', err.message);
    }
  });

  // ── Full MITRE re-sync — every Sunday at midnight ────────────────────────
  cron.schedule('0 0 * * 0', async () => {
    log.info('Weekly MITRE re-sync triggered');
    try {
      await runIngestion({ source: 'mitre' });
    } catch (err) {
      log.error('MITRE weekly re-sync failed:', err.message);
    }
  });

  log.info(`Ingestion scheduler started. Incremental: "${incrementalCron}" | MITRE weekly: Sundays 00:00`);
}

module.exports = { startScheduler };
