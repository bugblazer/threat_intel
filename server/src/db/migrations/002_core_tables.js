/**
 * Migration 002 — Core Tables
 *
 * Creates all five primary tables that map directly to the proposal schema.
 * JSONB columns absorb feed-specific fields so the core schema stays stable
 * as upstream formats evolve.
 *
 * DB Concepts demonstrated here:
 *   • JSON Columns  — platforms, external_refs, affected_products, pulse_tags
 *   • Indexing      — B-tree indexes on every lookup/filter column (migration 004)
 *   • Full-Text     — search_vector tsvector columns updated via triggers (migration 005)
 */

exports.up = async function (knex) {
  // ── techniques ────────────────────────────────────────────────────────────
  // Source: MITRE ATT&CK STIX bundle
  await knex.schema.createTable('techniques', (t) => {
    t.increments('id');
    t.string('technique_id', 20).notNullable().unique(); // e.g. T1059, T1059.001
    t.string('name', 255).notNullable();
    t.string('tactic', 100);                              // e.g. execution, persistence
    t.text('description');
    t.jsonb('platforms').defaultTo('[]');                 // ["Windows","Linux","macOS"]
    t.jsonb('kill_chain_phases').defaultTo('[]');         // [{phase_name, kill_chain_name}]
    t.jsonb('external_refs').defaultTo('[]');             // [{source_name, url, external_id}]
    t.boolean('is_subtechnique').defaultTo(false);
    t.string('parent_technique_id', 20);                  // FK-like; resolved in app layer
    t.timestamps(true, true);                             // created_at, updated_at
  });

  // ── cves ──────────────────────────────────────────────────────────────────
  // Source: NVD CVE Feed (NIST JSON API)
  await knex.schema.createTable('cves', (t) => {
    t.increments('id');
    t.string('cve_id', 20).notNullable().unique();        // CVE-2024-12345
    t.text('description');
    t.decimal('cvss_score', 4, 1);                        // 0.0 – 10.0
    t.string('cvss_version', 10);                         // 2.0 | 3.0 | 3.1 | 4.0
    t.string('cvss_vector', 100);
    t.string('severity', 20);                             // NONE|LOW|MEDIUM|HIGH|CRITICAL
    t.string('cwe_id', 20);                               // CWE-79, CWE-89 …
    t.jsonb('affected_products').defaultTo('[]');          // [{vendor, product, version}]
    t.jsonb('references').defaultTo('[]');                 // [{url, tags[]}]
    t.date('published_at');
    t.date('modified_at');
    // Full-text search vector — populated by trigger (migration 005)
    t.specificType('search_vector', 'tsvector');
    t.timestamps(true, true);
  });

  // ── threat_actors ─────────────────────────────────────────────────────────
  // Source: AlienVault OTX pulses + manual enrichment
  await knex.schema.createTable('threat_actors', (t) => {
    t.increments('id');
    t.string('name', 255).notNullable().unique();
    t.specificType('aliases', 'text[]').defaultTo('{}');
    t.string('country', 100);
    t.string('motivation', 100);                          // espionage|financial|hacktivism…
    t.text('description');
    t.specificType('technique_ids', 'text[]').defaultTo('{}'); // T#### references
    t.jsonb('meta').defaultTo('{}');                      // any extra OTX fields
    t.specificType('search_vector', 'tsvector');
    t.timestamps(true, true);
  });

  // ── iocs ──────────────────────────────────────────────────────────────────
  // Sources: Abuse.ch (MalwareBazaar, URLhaus, ThreatFox) + OTX
  await knex.schema.createTable('iocs', (t) => {
    t.increments('id');
    t.text('value').notNullable();                        // IP, hash, URL, domain
    t.string('type', 50).notNullable();                   // ip|domain|url|md5|sha256|sha1
    t.string('source_feed', 100);                         // malwarebazaar|urlhaus|threatfox|otx
    t.timestamp('first_seen');
    t.timestamp('last_seen');
    t.string('malware_family', 100);
    t.string('threat_type', 100);                         // botnet_cc|payload_delivery|…
    t.integer('linked_cve_id').references('id').inTable('cves').onDelete('SET NULL');
    t.integer('linked_technique_id').references('id').inTable('techniques').onDelete('SET NULL');
    t.integer('confidence').defaultTo(50);                // 0–100
    t.jsonb('tags').defaultTo('[]');
    t.jsonb('meta').defaultTo('{}');                      // feed-specific raw fields
    t.timestamps(true, true);

    // Composite unique: same IOC value from same feed = one row (upsert key)
    t.unique(['value', 'source_feed']);
  });

  // ── cve_technique_map ─────────────────────────────────────────────────────
  // Join table — the analytical heart of the system.
  // Links a vulnerability to the ATT&CK technique used to exploit it.
  await knex.schema.createTable('cve_technique_map', (t) => {
    t.increments('id');
    t.integer('cve_id').notNullable().references('id').inTable('cves').onDelete('CASCADE');
    t.integer('technique_id').notNullable().references('id').inTable('techniques').onDelete('CASCADE');
    t.decimal('confidence_score', 4, 2).defaultTo(1.0);  // 0.00 – 1.00
    t.string('source', 100);                              // nvd|otx|manual
    t.unique(['cve_id', 'technique_id']);
  });

  // ── users ─────────────────────────────────────────────────────────────────
  await knex.schema.createTable('users', (t) => {
    t.increments('id');
    t.string('email', 255).notNullable().unique();
    t.string('password_hash', 255).notNullable();
    t.enu('role', ['readonly', 'contributor', 'admin']).defaultTo('readonly');
    t.boolean('is_active').defaultTo(true);
    t.timestamps(true, true);
  });
};

exports.down = async function (knex) {
  await knex.schema
    .dropTableIfExists('cve_technique_map')
    .dropTableIfExists('iocs')
    .dropTableIfExists('threat_actors')
    .dropTableIfExists('cves')
    .dropTableIfExists('techniques')
    .dropTableIfExists('users');
};
