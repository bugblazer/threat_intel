/**
 * Migration 006 — Access Control (Row-Level Security + Role Grants)
 *
 * DB Concept: Access Control
 *
 * Three-layer model:
 *   Layer 1 — PostgreSQL roles (threat_readonly / threat_contributor / threat_admin)
 *   Layer 2 — Table-level GRANT/REVOKE aligned to each role's purpose
 *   Layer 3 — Row-Level Security (RLS) policies on the `users` table so that
 *              readonly analysts can only see their own row, not other users' data.
 *
 * JWT flow (handled in API middleware, referenced here for clarity):
 *   Client logs in → receives JWT with { role: "readonly" | "contributor" | "admin" }
 *   Each API request attaches the matching PG connection pool (db.js)
 *   PostgreSQL enforces permissions at the database level — not just in app code
 */

exports.up = async function (knex) {
  // ── readonly role ────────────────────────────────────────────────────────
  // Analysts: read all threat data, but only their own user row
  await knex.raw(`
    GRANT SELECT ON techniques, cves, threat_actors, iocs, cve_technique_map
      TO threat_readonly;

    -- Views inherit the definer's permissions, but we grant explicitly too
    GRANT SELECT ON high_severity_cves, active_iocs, technique_frequency
      TO threat_readonly;

    -- Sequence access not needed for readonly
  `);

  // ── contributor role ─────────────────────────────────────────────────────
  // Ingestion scripts: write threat data, cannot touch users table
  await knex.raw(`
    GRANT SELECT, INSERT, UPDATE, DELETE
      ON techniques, cves, threat_actors, iocs, cve_technique_map
      TO threat_contributor;

    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
      TO threat_contributor;

    -- Explicitly deny access to users table
    REVOKE ALL ON users FROM threat_contributor;
  `);

  // ── admin role ───────────────────────────────────────────────────────────
  // Full access — used by migrations and user management endpoints
  await knex.raw(`
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO threat_admin;
    GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO threat_admin;
  `);

  // ── Row-Level Security on users ───────────────────────────────────────────
  // Enable RLS; then define policies.
  // threat_readonly users can only SELECT their own row.
  // threat_admin bypasses RLS (BYPASSRLS privilege).
  await knex.raw(`
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;

    -- Readonly analysts see only their own row
    CREATE POLICY users_select_own
      ON users
      FOR SELECT
      TO threat_readonly
      USING (email = current_user);

    -- Admins can see and modify all rows (policy not strictly needed since
    -- BYPASSRLS is set, but explicit is clearer for demonstration purposes)
    CREATE POLICY users_admin_all
      ON users
      FOR ALL
      TO threat_admin
      USING (true)
      WITH CHECK (true);

    -- Give threat_readonly SELECT on users (RLS will restrict rows)
    GRANT SELECT ON users TO threat_readonly;

    -- Give threat_admin full access
    GRANT ALL ON users TO threat_admin;
  `);

  // Grant BYPASSRLS to admin role so migrations aren't blocked
  await knex.raw(`
    DO $$
    BEGIN
      ALTER ROLE threat_admin BYPASSRLS;
    EXCEPTION WHEN others THEN NULL; -- ignore if role doesn't support this
    END $$;
  `);
};

exports.down = async function (knex) {
  await knex.raw(`
    -- Remove RLS policies
    DROP POLICY IF EXISTS users_select_own ON users;
    DROP POLICY IF EXISTS users_admin_all  ON users;
    ALTER TABLE users DISABLE ROW LEVEL SECURITY;

    -- Revoke grants (best-effort; roles may not exist in all environments)
    REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM threat_readonly;
    REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM threat_contributor;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM threat_contributor;
  `);
};
