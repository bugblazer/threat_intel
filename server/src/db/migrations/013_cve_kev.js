/**
 * Migration 013 — CISA Known Exploited Vulnerabilities (KEV)
 *
 * Adds the KEV fields to `cves`. A CVE in the KEV catalog is being exploited in
 * the wild right now, which is a far stronger signal than a keyword link, so the
 * threat-informed sort weights it heavily.
 *
 *   kev_added_at    date CISA added it to the catalog (NULL = not in KEV)
 *   kev_due_date    remediation deadline CISA set for US federal agencies
 *   kev_ransomware  CISA reports known use in ransomware campaigns
 *
 * Existing table-level grants on `cves` cover the new columns.
 */

exports.up = async function (knex) {
  await knex.schema.alterTable('cves', (t) => {
    t.date('kev_added_at');
    t.date('kev_due_date');
    t.boolean('kev_ransomware').notNullable().defaultTo(false);
  });

  // Small partial index: only KEV rows, used by the "known exploited" filter and KPI.
  await knex.raw('CREATE INDEX idx_cves_kev ON cves (kev_added_at) WHERE kev_added_at IS NOT NULL');
};

exports.down = async function (knex) {
  await knex.raw('DROP INDEX IF EXISTS idx_cves_kev');
  await knex.schema.alterTable('cves', (t) => {
    t.dropColumn('kev_added_at');
    t.dropColumn('kev_due_date');
    t.dropColumn('kev_ransomware');
  });
};
