/**
 * Migration 004 — Indexes
 *
 * DB Concept: Indexing
 *
 * Strategy:
 *   • B-tree  — equality lookups and range queries on scalar columns
 *               (CVE IDs, CVSS scores, timestamps, enum values)
 *   • GIN     — full-text search vectors + JSONB containment queries
 *               (@> operator on affected_products, platforms, tags)
 *   • GiST    — trigram similarity (pg_trgm) for fuzzy IOC value search
 *
 * Every index here directly corresponds to a query pattern used by the API.
 * Comments note which endpoint benefits.
 */

exports.up = async function (knex) {
  // ── techniques ─────────────────────────────────────────────────────────
  // GET /api/v1/techniques/:technique_id
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_techniques_technique_id
    ON techniques (technique_id);`);

  // Filter by tactic in ATT&CK heatmap query
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_techniques_tactic
    ON techniques (tactic);`);

  // JSONB GIN: WHERE platforms @> '["Windows"]'
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_techniques_platforms_gin
    ON techniques USING GIN (platforms);`);

  // ── cves ───────────────────────────────────────────────────────────────
  // GET /api/v1/cves/:cve_id
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_cves_cve_id
    ON cves (cve_id);`);

  // CVE Explorer: ORDER BY cvss_score DESC, filter severity
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_cves_cvss_score
    ON cves (cvss_score DESC NULLS LAST);`);

  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_cves_severity
    ON cves (severity);`);

  // Date range filter: published in last 90 days
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_cves_published_at
    ON cves (published_at DESC);`);

  // Full-text search vector (GIN — required for tsvector queries)
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_cves_search_vector
    ON cves USING GIN (search_vector);`);

  // JSONB: WHERE affected_products @> '[{"vendor":"microsoft"}]'
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_cves_affected_products_gin
    ON cves USING GIN (affected_products);`);

  // ── iocs ───────────────────────────────────────────────────────────────
  // GET /api/v1/iocs?type=ip&value=...
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_iocs_type
    ON iocs (type);`);

  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_iocs_source_feed
    ON iocs (source_feed);`);

  // Timeline queries: ORDER BY last_seen DESC
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_iocs_last_seen
    ON iocs (last_seen DESC NULLS LAST);`);

  // Malware family filter
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_iocs_malware_family
    ON iocs (malware_family);`);

  // GiST trigram index: LIKE / similarity search on IOC value
  // e.g. WHERE value % '192.168' (similarity) or WHERE value ILIKE '%cobalt%'
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm
    ON iocs USING GIST (value gist_trgm_ops);`);

  // JSONB tags: WHERE tags @> '["Cobalt Strike"]'
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_iocs_tags_gin
    ON iocs USING GIN (tags);`);

  // ── cve_technique_map ──────────────────────────────────────────────────
  // Correlation queries from both directions
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_ctm_cve_id
    ON cve_technique_map (cve_id);`);

  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_ctm_technique_id
    ON cve_technique_map (technique_id);`);

  // ── threat_actors ──────────────────────────────────────────────────────
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_threat_actors_search_vector
    ON threat_actors USING GIN (search_vector);`);

  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_threat_actors_country
    ON threat_actors (country);`);

  // ── users ──────────────────────────────────────────────────────────────
  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_users_email
    ON users (email);`);

  await knex.raw(`CREATE INDEX IF NOT EXISTS idx_users_role
    ON users (role);`);
};

exports.down = async function (knex) {
  const indexes = [
    'idx_techniques_technique_id', 'idx_techniques_tactic', 'idx_techniques_platforms_gin',
    'idx_cves_cve_id', 'idx_cves_cvss_score', 'idx_cves_severity',
    'idx_cves_published_at', 'idx_cves_search_vector', 'idx_cves_affected_products_gin',
    'idx_iocs_type', 'idx_iocs_source_feed', 'idx_iocs_last_seen',
    'idx_iocs_malware_family', 'idx_iocs_value_trgm', 'idx_iocs_tags_gin',
    'idx_ctm_cve_id', 'idx_ctm_technique_id',
    'idx_threat_actors_search_vector', 'idx_threat_actors_country',
    'idx_users_email', 'idx_users_role',
  ];
  for (const idx of indexes) {
    await knex.raw(`DROP INDEX IF EXISTS ${idx};`);
  }
};
