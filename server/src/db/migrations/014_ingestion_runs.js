/**
 * Migration 014 — Ingestion run history
 *
 * Ingestion status used to live in a variable in the API process: a restart
 * forgot the last run, scheduled runs never showed up at all, and nothing stopped
 * a manual run from starting while a scheduled one was still going.
 *
 * Every run (scheduled, manual or CLI) now gets a row here. The partial unique
 * index allows at most ONE row with status 'running', so the database itself
 * refuses a second concurrent run, even across processes.
 */

exports.up = async function (knex) {
  await knex.schema.createTable('ingestion_runs', (t) => {
    t.increments('id');
    t.string('trigger', 20).notNullable();          // 'schedule' | 'manual' | 'cli'
    t.string('triggered_by', 255);                  // email for manual runs
    t.string('source', 20);                         // NULL = all sources
    t.boolean('full_sync').notNullable().defaultTo(false);
    t.string('status', 20).notNullable();           // running | succeeded | partial | failed | interrupted
    t.jsonb('results').defaultTo('{}');             // per-source counts
    t.jsonb('errors').defaultTo('{}');              // per-source error messages
    t.timestamp('started_at').notNullable().defaultTo(knex.fn.now());
    t.timestamp('finished_at');
  });

  await knex.raw(`
    CREATE UNIQUE INDEX ingestion_runs_one_running ON ingestion_runs ((true)) WHERE status = 'running';
    CREATE INDEX ingestion_runs_started_at_idx ON ingestion_runs (started_at DESC);

    GRANT SELECT, INSERT, UPDATE ON ingestion_runs TO threat_contributor;
    GRANT ALL ON ingestion_runs TO threat_admin;
    GRANT USAGE, SELECT ON SEQUENCE ingestion_runs_id_seq TO threat_contributor, threat_admin;
  `);
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists('ingestion_runs');
};
