/**
 * Migration 011 — Contributor View Grants (bugfix)
 *
 * Migration 006 granted SELECT on the pre-built views to threat_readonly and
 * threat_admin, but NOT to threat_contributor. Contributors therefore hit
 * "permission denied for view active_iocs" on the dashboard, IOC page,
 * high-severity CVE list, and ATT&CK heatmap — all of which read from views.
 *
 * Contributors already have SELECT on the underlying base tables (migration
 * 006); this simply extends the same read access to the views built on them.
 */

exports.up = async function (knex) {
  await knex.raw(`
    GRANT SELECT ON high_severity_cves, active_iocs, technique_frequency
      TO threat_contributor;
  `);
};

exports.down = async function (knex) {
  await knex.raw(`
    REVOKE SELECT ON high_severity_cves, active_iocs, technique_frequency
      FROM threat_contributor;
  `);
};
