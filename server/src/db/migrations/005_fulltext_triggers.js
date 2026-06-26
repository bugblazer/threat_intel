/**
 * Migration 005 — Full-Text Search Triggers
 *
 * DB Concept: Full-Text Search
 *
 * PostgreSQL tsvector/tsquery workflow:
 *   1. Each searchable table has a `search_vector tsvector` column.
 *   2. A BEFORE INSERT OR UPDATE trigger calls a PL/pgSQL function that
 *      rebuilds the vector from the relevant text columns.
 *   3. The vector is weighted: title/ID fields get weight 'A' (highest),
 *      description fields get weight 'B'.
 *   4. A GIN index on the vector column enables sub-millisecond lookups
 *      (created in migration 004).
 *
 * Query pattern used by the API:
 *   WHERE search_vector @@ plainto_tsquery('english', $1)
 *   ORDER BY ts_rank(search_vector, plainto_tsquery('english', $1)) DESC
 */

exports.up = async function (knex) {
  // ── CVE full-text trigger ────────────────────────────────────────────────
  await knex.raw(`
    CREATE OR REPLACE FUNCTION cves_search_vector_update() RETURNS trigger AS $$
    BEGIN
      NEW.search_vector :=
        -- CVE ID weighted A (most relevant for exact lookups)
        setweight(to_tsvector('english', COALESCE(NEW.cve_id, '')), 'A') ||
        -- CWE ID weighted B
        setweight(to_tsvector('english', COALESCE(NEW.cwe_id, '')), 'B') ||
        -- Description weighted B
        setweight(to_tsvector('english', COALESCE(NEW.description, '')), 'B') ||
        -- Severity weighted C
        setweight(to_tsvector('english', COALESCE(NEW.severity, '')), 'C');
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trig_cves_search_vector ON cves;

    CREATE TRIGGER trig_cves_search_vector
      BEFORE INSERT OR UPDATE OF cve_id, description, cwe_id, severity
      ON cves
      FOR EACH ROW EXECUTE FUNCTION cves_search_vector_update();
  `);

  // ── Threat actor full-text trigger ───────────────────────────────────────
  await knex.raw(`
    CREATE OR REPLACE FUNCTION threat_actors_search_vector_update() RETURNS trigger AS $$
    BEGIN
      NEW.search_vector :=
        setweight(to_tsvector('english', COALESCE(NEW.name, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(array_to_string(NEW.aliases, ' '), '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.country, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.motivation, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.description, '')), 'C');
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trig_threat_actors_search_vector ON threat_actors;

    CREATE TRIGGER trig_threat_actors_search_vector
      BEFORE INSERT OR UPDATE OF name, aliases, country, motivation, description
      ON threat_actors
      FOR EACH ROW EXECUTE FUNCTION threat_actors_search_vector_update();
  `);

  // ── Technique full-text (stored inline, not a separate tsvector column) ──
  // Techniques are searched via the GiST trigram index on name + technique_id
  // (set up in migration 004) rather than a tsvector, because the MITRE dataset
  // is small enough (~600 rows) that trigram similarity gives better UX
  // (fuzzy match) for analyst search bars.
};

exports.down = async function (knex) {
  await knex.raw(`
    DROP TRIGGER IF EXISTS trig_cves_search_vector ON cves;
    DROP FUNCTION IF EXISTS cves_search_vector_update();

    DROP TRIGGER IF EXISTS trig_threat_actors_search_vector ON threat_actors;
    DROP FUNCTION IF EXISTS threat_actors_search_vector_update();
  `);
};
