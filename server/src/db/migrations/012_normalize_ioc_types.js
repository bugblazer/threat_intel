/**
 * Migration 012 — Normalise IOC types (data fix)
 *
 * ThreatFox labelled SHA-1 hashes "sha1_hash" while OTX produced "sha1", so the
 * same kind of indicator appeared as two types on the dashboard and in filters.
 * Ingestion now runs every type through lib/indicators.normalizeIocType; this
 * migration rewrites rows that were stored before that fix.
 *
 * Changing `type` can't collide with UNIQUE(value, source_feed), so a plain
 * UPDATE is safe.
 */

const RENAMES = {
  sha1_hash:   'sha1',
  md5_hash:    'md5',
  sha256_hash: 'sha256',
  'ip:port':   'ip',
  hostname:    'domain',
};

exports.up = async function (knex) {
  for (const [from, to] of Object.entries(RENAMES)) {
    await knex('iocs').where('type', from).update({ type: to });
  }
};

// The old labels can't be told apart once merged, and nothing depends on them.
exports.down = async function () {};
