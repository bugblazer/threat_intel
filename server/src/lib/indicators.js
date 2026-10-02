/**
 * indicators.js — Shared helpers for indicators of compromise (IOCs)
 *
 * normalizeIocType: every feed names indicator types differently (ThreatFox says
 * "sha1_hash", OTX says "FileHash-SHA1", URLhaus just stores the hash). Without one
 * vocabulary the same kind of indicator shows up as two or three "types" in the UI
 * and in the stats. All ingestion sources run their types through this function.
 *
 * refang: turns defanged indicators pasted from reports back into real ones,
 * e.g. 1[.]2[.]3[.]4, hxxp://evil, evil(dot)com.
 */

// Canonical types: ip | domain | url | md5 | sha1 | sha256 | email | other ones pass through.
const TYPE_ALIASES = {
  'ip:port':         'ip',
  'ipv4':            'ip',
  'ipv6':            'ip',
  'ip':              'ip',
  'hostname':        'domain',
  'domain':          'domain',
  'url':             'url',
  'uri':             'url',
  'md5':             'md5',
  'md5_hash':        'md5',
  'filehash-md5':    'md5',
  'sha1':            'sha1',
  'sha1_hash':       'sha1',
  'filehash-sha1':   'sha1',
  'sha256':          'sha256',
  'sha256_hash':     'sha256',
  'filehash-sha256': 'sha256',
  'email':           'email',
};

/**
 * Map a feed-specific indicator type to the platform's canonical type.
 * Unknown types are lowercased and returned as-is (never dropped), so a new
 * feed type shows up in the UI instead of silently disappearing.
 */
function normalizeIocType(rawType) {
  if (!rawType) return 'unknown';
  const key = String(rawType).trim().toLowerCase();
  return TYPE_ALIASES[key] ?? key;
}

function refang(raw) {
  return String(raw)
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.\}|\(dot\)|\[dot\]/gi, '.')
    .replace(/\[@\]|\(at\)|\[at\]/gi, '@')
    .replace(/^h(?:xx|XX)?p(s?):\/\//i, 'http$1://');
}

module.exports = { normalizeIocType, refang, TYPE_ALIASES };
