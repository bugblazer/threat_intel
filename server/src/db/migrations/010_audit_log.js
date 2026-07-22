/**
 * Migration 010 — Audit Log
 *
 * DB Concept: Access Control (accountability for privileged actions)
 *
 * Records sensitive admin actions — role changes, deactivations, role-request
 * decisions, ingestion triggers — so admins have a "who did what, when" trail.
 * This complements the row-level attribution added for detection coverage.
 *
 * Only threat_admin reads/writes this table (all audited actions run through
 * the admin pool), so we grant it explicitly and leave it out of RLS.
 */

exports.up = async function (knex) {
  await knex.schema.createTable('audit_log', (t) => {
    t.increments('id');
    t.integer('actor_id');                 // user id of the acting admin (nullable for system)
    t.string('actor_email', 255);          // denormalised for easy display
    t.string('action', 100).notNullable(); // e.g. 'user.role_changed', 'ingestion.triggered'
    t.string('target_type', 50);           // 'user' | 'role_request' | 'ingestion' | ...
    t.string('target_id', 100);            // id/email of the affected entity
    t.jsonb('detail').defaultTo('{}');     // structured before/after or extra context
    t.timestamp('created_at').defaultTo(knex.fn.now());
  });

  await knex.schema.alterTable('audit_log', (t) => {
    t.index(['created_at'], 'audit_log_created_at_idx');
    t.index(['action'],     'audit_log_action_idx');
  });

  await knex.raw(`
    GRANT ALL ON audit_log TO threat_admin;
    GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO threat_admin;
  `);
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists('audit_log');
};
