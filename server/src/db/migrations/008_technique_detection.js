/**
 * Migration 008 — Technique Detection Coverage
 *
 * DB Concept: Access Control (contributor-writable operational metadata)
 *
 * Adds a `detection_status` column to techniques so a team can track which
 * ATT&CK techniques they can currently detect. This turns the read-only
 * frequency heatmap into a gap-analysis tool ("where are we blind?").
 *
 *   none      — no detection coverage (default)
 *   partial   — some coverage / low confidence
 *   detected  — reliable detection in place
 *
 * Contributors already hold UPDATE on `techniques` (migration 006), so the
 * table-level grant automatically extends to this new column — no extra GRANT
 * is required.
 */

exports.up = async function (knex) {
  await knex.schema.alterTable('techniques', (t) => {
    t.enu('detection_status', ['none', 'partial', 'detected'])
      .notNullable()
      .defaultTo('none');
    t.text('detection_notes');
  });
};

exports.down = async function (knex) {
  await knex.schema.alterTable('techniques', (t) => {
    t.dropColumn('detection_status');
    t.dropColumn('detection_notes');
  });
};
