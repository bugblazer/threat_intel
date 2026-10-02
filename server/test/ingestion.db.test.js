/**
 * The "one ingestion at a time" rule is enforced by a partial unique index
 * (migration 014), not by application code. Skipped without a database.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { pools } = require('../src/db/db');
const { runIngestion, IngestionBusyError } = require('../src/ingestion/index');

const db = pools.contributor;
let dbUp = false;
let blockerId;

test.before(async () => {
  try { await db.raw('SELECT 1 FROM ingestion_runs LIMIT 1'); dbUp = true; } catch { /* skip */ }
});

test.after(async () => {
  if (blockerId) await pools.admin('ingestion_runs').where({ id: blockerId }).del();
  await Promise.all(Object.values(pools).map(p => p.destroy()));
});

test('a second run is refused while one is running', async (t) => {
  if (!dbUp) return t.skip('database not available');
  if (await db('ingestion_runs').where({ status: 'running' }).first()) return t.skip('a real run is in progress');

  [{ id: blockerId }] = await db('ingestion_runs')
    .insert({ trigger: 'cli', triggered_by: 'test', status: 'running' })
    .returning(['id']);

  await assert.rejects(
    runIngestion({ source: 'mitre', trigger: 'cli' }),
    err => err instanceof IngestionBusyError,
  );
});
