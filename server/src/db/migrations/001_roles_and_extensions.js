/**
 * Migration 001 — Roles & Extensions
 *
 * Creates the three application-level PostgreSQL roles and enables the
 * pg_trgm extension (needed for full-text similarity search).
 *
 * Roles:
 *   threat_readonly    — analysts; SELECT only on public schema
 *   threat_contributor — ingestion scripts; INSERT/UPDATE/DELETE on data tables
 *   threat_admin       — schema owner; all privileges (used by migrations)
 *
 * NOTE: Roles are cluster-level objects. We use IF NOT EXISTS so re-running
 * this migration (e.g. in CI) doesn't error if roles already exist.
 */

exports.up = async function (knex) {
  await knex.raw(`
    -- Extensions
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";
    CREATE EXTENSION IF NOT EXISTS "unaccent";

    -- Roles (passwords are set by the DBA / setup script, not here)
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'threat_readonly') THEN
        CREATE ROLE threat_readonly NOLOGIN;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'threat_contributor') THEN
        CREATE ROLE threat_contributor NOLOGIN;
      END IF;
      -- threat_admin is the superuser that runs migrations;
      -- create a login user for it if running fresh
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'threat_admin') THEN
        CREATE ROLE threat_admin LOGIN PASSWORD 'changeme' CREATEDB;
      END IF;
    END
    $$;

    -- Grant schema usage to all roles
    GRANT USAGE ON SCHEMA public TO threat_readonly, threat_contributor;
  `);
};

exports.down = async function (knex) {
  // Roles can't be dropped if they own objects — handled manually
  await knex.raw(`
    DROP EXTENSION IF EXISTS pg_trgm;
    DROP EXTENSION IF EXISTS unaccent;
  `);
};
