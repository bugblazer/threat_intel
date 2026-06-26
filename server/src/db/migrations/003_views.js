/**
 * Migration 003 — Views
 *
 * Creates three pre-built views consumed directly by API endpoints.
 * Views encapsulate complex JOIN/aggregate logic so route handlers stay thin.
 *
 * DB Concept: Views
 *
 *   high_severity_cves      — CVEs with CVSS ≥ 7.0 joined to their mapped techniques.
 *                             Powers the CVE Explorer's "High Severity" filter.
 *
 *   active_iocs             — Most recent IOC per (value, type) with source feed metadata.
 *                             Powers the IOC Search page.
 *
 *   technique_frequency     — ATT&CK techniques ranked by total IOC + CVE co-occurrences.
 *                             Powers the ATT&CK heatmap colour intensity.
 */

exports.up = async function (knex) {
  // ── high_severity_cves ────────────────────────────────────────────────────
  await knex.raw(`
    CREATE OR REPLACE VIEW high_severity_cves AS
    SELECT
      c.id,
      c.cve_id,
      c.description,
      c.cvss_score,
      c.severity,
      c.cwe_id,
      c.published_at,
      c.affected_products,
      -- Aggregate all linked techniques as a JSON array
      COALESCE(
        json_agg(
          json_build_object(
            'technique_id', t.technique_id,
            'name',         t.name,
            'tactic',       t.tactic,
            'confidence',   ctm.confidence_score
          )
        ) FILTER (WHERE t.id IS NOT NULL),
        '[]'
      ) AS techniques
    FROM cves c
    LEFT JOIN cve_technique_map ctm ON ctm.cve_id = c.id
    LEFT JOIN techniques t          ON t.id = ctm.technique_id
    WHERE c.cvss_score >= 7.0
    GROUP BY c.id
    ORDER BY c.cvss_score DESC, c.published_at DESC;
  `);

  // ── active_iocs ───────────────────────────────────────────────────────────
  await knex.raw(`
    CREATE OR REPLACE VIEW active_iocs AS
    SELECT
      i.id,
      i.value,
      i.type,
      i.source_feed,
      i.first_seen,
      i.last_seen,
      i.malware_family,
      i.threat_type,
      i.confidence,
      i.tags,
      -- Linked CVE info (nullable)
      c.cve_id          AS linked_cve,
      c.cvss_score      AS linked_cvss,
      -- Linked technique info (nullable)
      t.technique_id    AS linked_technique,
      t.name            AS linked_technique_name,
      t.tactic          AS linked_tactic
    FROM iocs i
    LEFT JOIN cves       c ON c.id = i.linked_cve_id
    LEFT JOIN techniques t ON t.id = i.linked_technique_id
    ORDER BY i.last_seen DESC NULLS LAST;
  `);

  // ── technique_frequency ───────────────────────────────────────────────────
  await knex.raw(`
    CREATE OR REPLACE VIEW technique_frequency AS
    SELECT
      t.id,
      t.technique_id,
      t.name,
      t.tactic,
      t.is_subtechnique,
      t.platforms,
      -- Count of distinct IOCs linked to this technique
      COUNT(DISTINCT i.id)   AS ioc_count,
      -- Count of distinct CVEs linked to this technique
      COUNT(DISTINCT ctm.cve_id) AS cve_count,
      -- Combined frequency score used for heatmap colour intensity
      (COUNT(DISTINCT i.id) + COUNT(DISTINCT ctm.cve_id)) AS total_frequency
    FROM techniques t
    LEFT JOIN iocs           i   ON i.linked_technique_id = t.id
    LEFT JOIN cve_technique_map ctm ON ctm.technique_id   = t.id
    GROUP BY t.id
    ORDER BY total_frequency DESC;
  `);
};

exports.down = async function (knex) {
  await knex.raw(`
    DROP VIEW IF EXISTS technique_frequency;
    DROP VIEW IF EXISTS active_iocs;
    DROP VIEW IF EXISTS high_severity_cves;
  `);
};
