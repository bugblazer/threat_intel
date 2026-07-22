/**
 * Migration 009 — Detection Coverage Attribution
 *
 * Adds accountability to the shared detection_status field: who last changed a
 * technique's coverage, and when. Detection coverage is team-owned (a single
 * shared value per technique), so an audit trail matters more than per-user
 * copies — these columns provide it without fragmenting the data.
 *
 * Contributors already hold UPDATE on `techniques` (migration 006); the
 * table-level grant extends to these new columns automatically.
 */

exports.up = async function (knex) {
  await knex.schema.alterTable('techniques', (t) => {
    t.string('detection_updated_by', 255); // email of the contributor/admin who set it
    t.timestamp('detection_updated_at');
  });
};

exports.down = async function (knex) {
  await knex.schema.alterTable('techniques', (t) => {
    t.dropColumn('detection_updated_by');
    t.dropColumn('detection_updated_at');
  });
};
