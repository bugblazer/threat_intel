/**
 * linker.js — Post-Ingestion Cross-Source Linker
 *
 * Runs after all four source ingestions complete. Populates:
 *
 *   cve_technique_map   — links CVEs to ATT&CK techniques by:
 *                         1. Regex scanning CVE descriptions for T#### IDs
 *                         2. Keyword matching (e.g. "phishing" → T1566)
 *
 *   iocs.linked_technique_id — links IOCs to techniques by matching
 *                              malware_family and tags against a keyword map
 *                              (e.g. "cobalt strike" → T1059, "mimikatz" → T1003)
 *
 * This is what makes the technique_frequency view non-zero, which in turn
 * makes the ATT&CK heatmap colour intensity meaningful.
 *
 * DB Concepts exercised:
 *   Views    — technique_frequency view is the consumer of these links
 *   Indexing — uses idx_ctm_technique_id, idx_iocs_malware_family
 *   JSONB    — reads iocs.tags JSONB column for keyword matching
 */

const { makeLogger } = require('../utils/logger');

// ── Keyword → technique_id map ────────────────────────────────────────────────
// Maps lowercase keywords found in CVE descriptions or IOC metadata to the
// most relevant ATT&CK technique. Ordered from most specific to least.
const KEYWORD_TECHNIQUE_MAP = [
  // Execution
  { keywords: ['powershell'],                         technique: 'T1059.001' },
  { keywords: ['cmd.exe', 'command shell', 'cmd /c'], technique: 'T1059.003' },
  { keywords: ['bash', 'shell script', '/bin/sh'],    technique: 'T1059.004' },
  { keywords: ['python script', 'python payload'],    technique: 'T1059.006' },
  { keywords: ['javascript', 'jscript', 'wscript'],  technique: 'T1059.007' },
  { keywords: ['mshta', 'hta file'],                  technique: 'T1218.005' },
  { keywords: ['regsvr32'],                            technique: 'T1218.010' },
  { keywords: ['rundll32'],                            technique: 'T1218.011' },

  // Credential Access
  { keywords: ['mimikatz', 'lsass', 'credential dump', 'pass-the-hash', 'pass the hash'], technique: 'T1003' },
  { keywords: ['brute force', 'brute-force', 'password spray', 'credential stuffing'],    technique: 'T1110' },
  { keywords: ['kerberoasting', 'kerberos ticket'],   technique: 'T1558.003' },
  { keywords: ['golden ticket', 'silver ticket'],     technique: 'T1558.001' },

  // Initial Access
  { keywords: ['phishing', 'spearphishing', 'spear phishing'], technique: 'T1566' },
  { keywords: ['watering hole', 'drive-by'],          technique: 'T1189' },
  { keywords: ['supply chain', 'dependency confusion'], technique: 'T1195' },
  { keywords: ['valid account', 'stolen credential'], technique: 'T1078' },
  { keywords: ['external remote service', 'vpn access'], technique: 'T1133' },
  { keywords: ['exploit public-facing', 'remote code execution', 'rce'],  technique: 'T1190' },

  // Persistence
  { keywords: ['registry run key', 'registry persistence', 'hkcu\\software\\microsoft\\windows\\currentversion\\run'], technique: 'T1547.001' },
  { keywords: ['scheduled task', 'cron job', 'at.exe'], technique: 'T1053' },
  { keywords: ['web shell', 'webshell'],              technique: 'T1505.003' },
  { keywords: ['bootkit', 'boot sector'],             technique: 'T1542.003' },

  // Defense Evasion
  { keywords: ['obfuscat', 'base64 encoded', 'encoded payload'], technique: 'T1027' },
  { keywords: ['process inject', 'dll inject', 'process hollowing'], technique: 'T1055' },
  { keywords: ['disable antivirus', 'disable defender', 'tamper protection'], technique: 'T1562' },
  { keywords: ['masquerad'],                          technique: 'T1036' },
  { keywords: ['rootkit'],                            technique: 'T1014' },

  // Discovery
  { keywords: ['network scan', 'port scan', 'nmap'],  technique: 'T1046' },
  { keywords: ['system information', 'os fingerprint'], technique: 'T1082' },
  { keywords: ['active directory', 'ldap query', 'domain enumeration'], technique: 'T1087.002' },

  // Lateral Movement
  { keywords: ['lateral movement', 'pass-the-ticket', 'overpass-the-hash'], technique: 'T1550' },
  { keywords: ['remote desktop', 'rdp'],              technique: 'T1021.001' },
  { keywords: ['smb', 'psexec', 'wmi lateral'],       technique: 'T1021.002' },

  // Collection
  { keywords: ['keylogger', 'keylogging'],            technique: 'T1056.001' },
  { keywords: ['screen capture', 'screenshot'],       technique: 'T1113' },
  { keywords: ['clipboard'],                          technique: 'T1115' },

  // Command and Control
  { keywords: ['cobalt strike', 'beacon', 'cs beacon'], technique: 'T1071' },
  { keywords: ['c2', 'command and control', 'command-and-control'], technique: 'T1071' },
  { keywords: ['dns tunnel', 'dns exfil'],             technique: 'T1071.004' },
  { keywords: ['tor ', ' tor,', 'onion'],              technique: 'T1090.003' },

  // Exfiltration
  { keywords: ['data exfil', 'exfiltrat'],             technique: 'T1041' },
  { keywords: ['ftp exfil', 'sftp upload'],            technique: 'T1048.003' },

  // Impact
  { keywords: ['ransomware', 'encrypt files', 'file encryption'], technique: 'T1486' },
  { keywords: ['wiper', 'disk wipe', 'mbr overwrite'], technique: 'T1561' },
  { keywords: ['ddos', 'denial of service', 'dos attack'], technique: 'T1498' },

  // ── Vulnerability exploitation phrasing ─────────────────────────────────────
  // The single biggest gap: the most common phrases in NVD CVE descriptions were
  // not mapped at all, so the vast majority of CVEs produced zero technique links
  // and whole tactic columns stayed empty. These map how an attacker leverages a
  // class of flaw to a representative ATT&CK technique.
  { keywords: ['privilege escalation', 'elevation of privilege', 'escalate privileges', 'gain privileges', 'gain elevated', 'local privilege'], technique: 'T1068' },
  { keywords: ['buffer overflow', 'heap overflow', 'stack overflow', 'heap-based buffer overflow', 'stack-based buffer overflow', 'use after free', 'use-after-free', 'out-of-bounds write', 'out of bounds write', 'out-of-bounds read', 'memory corruption', 'type confusion', 'double free', 'integer overflow'], technique: 'T1203' },
  { keywords: ['command injection', 'os command injection', 'argument injection', 'arbitrary command'], technique: 'T1059' },
  { keywords: ['sql injection', 'sqli'],               technique: 'T1190' },
  { keywords: ['authentication bypass', 'bypass authentication', 'improper authentication', 'auth bypass', 'authorization bypass'], technique: 'T1078' },
  { keywords: ['insecure deserialization', 'deserialization of untrusted', 'unsafe deserialization'], technique: 'T1190' },
  { keywords: ['server-side request forgery', 'ssrf'], technique: 'T1190' },
  { keywords: ['cross-site scripting', 'stored cross-site', 'reflected cross-site', 'xss'], technique: 'T1059.007' },
  { keywords: ['endpoint denial of service', 'null pointer dereference', 'application crash', 'service crash', 'reachable assertion'], technique: 'T1499' },

  // ── Malware families → their primary technique ──────────────────────────────
  // Ransomware
  { keywords: ['lockbit', 'conti', 'ryuk', 'blackcat', 'alphv', 'royal ransomware', 'akira', 'hive ransomware', 'clop', 'black basta', 'blackbasta', 'medusa', 'play ransomware', 'revil', 'sodinokibi', 'maze', 'hellokitty', 'wannacry', 'notpetya', 'phobos', 'rhysida', 'stop djvu'], technique: 'T1486' },
  // Loaders / droppers
  { keywords: ['emotet', 'qbot', 'qakbot', 'smokeloader', 'gootloader', 'bumblebee', 'icedid', 'bazarloader', 'guloader', 'amadey', 'darkgate', 'pikabot', 'matanbuchus'], technique: 'T1105' },
  // Remote access trojans
  { keywords: ['njrat', 'asyncrat', 'quasarrat', 'quasar rat', 'nanocore', 'remcos', 'xworm', 'netwire', 'warzone', 'orcus', 'adwind', 'revenge rat', 'venomrat'], technique: 'T1219' },
  // Info-stealers
  { keywords: ['redline', 'redlinestealer', 'vidar', 'raccoon', 'lumma', 'lummastealer', 'stealc', 'azorult', 'lokibot', 'mars stealer', 'rhadamanthys', 'aurora stealer', 'xloader'], technique: 'T1555' },
  // Keyloggers
  { keywords: ['agenttesla', 'agent tesla', 'snake keylogger', 'formbook'], technique: 'T1056.001' },
  // Banking trojans (heavy process injection)
  { keywords: ['trickbot', 'dridex', 'gozi', 'ursnif', 'isfb', 'zloader', 'bokbot'], technique: 'T1055' },
  // C2 frameworks
  { keywords: ['cobaltstrike', 'sliver', 'mythic', 'havoc', 'brute ratel', 'bruteratel', 'posh c2', 'covenant'], technique: 'T1071' },
  { keywords: ['metasploit', 'meterpreter'],           technique: 'T1059' },
  // Coin miners
  { keywords: ['xmrig', 'coinminer', 'cryptominer', 'monero miner'], technique: 'T1496' },
  // Proxy / botnet infrastructure
  { keywords: ['systembc', 'socks5systemz'],           technique: 'T1090' },

  // ── IOC threat-type signals (weakest — kept last so a known family wins) ────
  { keywords: ['payload delivery', 'malware download', 'malware distribution'], technique: 'T1105' },
  { keywords: ['botnet', 'botnet cc', 'c2 server'],    technique: 'T1071' },
];

// Regex to find explicit T#### or T####.### references in text
const TECHNIQUE_ID_REGEX = /\bT\d{4}(?:\.\d{3})?\b/g;

// BUG FIX: keyword matching used plain substring `includes()`, so short
// keywords caused heavy false positives — "rce" matched "force"/"resource",
// "c2" matched "ec2", etc. Precompile word-boundary regexes instead.
const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const COMPILED_KEYWORD_MAP = KEYWORD_TECHNIQUE_MAP.map(({ keywords, technique }) => ({
  technique,
  regexes: keywords.map(kw =>
    new RegExp(`(^|[^a-z0-9])${escapeRe(kw.trim())}([^a-z0-9]|$)`, 'i')),
}));

/**
 * Resolve a technique_id string to a { dbId, resolved } pair via the lookup map.
 * Falls back to the parent technique when a sub-technique isn't present in the
 * DB (e.g. "T1059.001" → "T1059"), so a strong match is never lost just because
 * the exact sub-technique wasn't ingested.
 */
function resolveTechnique(techId, techMap) {
  if (!techId) return null;
  if (techMap.has(techId)) return { dbId: techMap.get(techId), resolved: techId };
  if (techId.includes('.')) {
    const parent = techId.split('.')[0];
    if (techMap.has(parent)) return { dbId: techMap.get(parent), resolved: parent };
  }
  return null; // genuinely not in the DB — skip this hit
}

/**
 * Find ALL matching techniques for a block of text, most-confident first.
 * Returns an array of { dbId, technique_id, confidence, source } (deduped, capped).
 *
 * Collecting multiple matches — instead of only the first — is what gives the
 * ATT&CK heatmap real spread instead of one or two dominant cells.
 *
 * BUG FIX: the previous version returned a keyword's technique WITHOUT checking
 * it existed in the DB. If that technique was absent, the caller dropped the
 * whole row instead of trying the next keyword. resolveTechnique() now filters
 * every hit (and falls back to the parent), so a valid lower-priority match wins.
 */
function findTechniques(text, techMap, { max = 4 } = {}) {
  if (!text) return [];
  const out = new Map(); // resolved technique_id → entry

  // 1. Explicit T#### IDs in the text — highest confidence
  for (const id of text.match(TECHNIQUE_ID_REGEX) ?? []) {
    const r = resolveTechnique(id, techMap);
    if (r && !out.has(r.resolved)) {
      out.set(r.resolved, { dbId: r.dbId, technique_id: r.resolved, confidence: 0.90, source: 'auto-regex' });
    }
  }

  // 2. Keyword matches, ordered most→least specific
  for (const { regexes, technique } of COMPILED_KEYWORD_MAP) {
    if (out.size >= max) break;
    if (regexes.some(re => re.test(text))) {
      const r = resolveTechnique(technique, techMap);
      if (r && !out.has(r.resolved)) {
        out.set(r.resolved, { dbId: r.dbId, technique_id: r.resolved, confidence: 0.60, source: 'auto-keyword' });
      }
    }
  }

  return [...out.values()].slice(0, max);
}

/** Single best technique for a text (IOCs hold one FK). */
function findBestTechnique(text, techMap) {
  return findTechniques(text, techMap, { max: 1 })[0] ?? null;
}

/**
 * Normalize metadata so single-token / camelCase / underscored malware family
 * names match the spaced keywords in the map:
 *   "CobaltStrike" → "Cobalt Strike",  "botnet_cc" → "botnet cc".
 * We search both the original text and this normalized form.
 */
function normalizeMeta(text) {
  return String(text)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // split camelCase
    .replace(/[_\-]+/g, ' ');               // underscores/dashes → spaces
}

/**
 * Main linking function — runs after all sources have been ingested.
 * @param {import('knex').Knex} db — contributor pool
 */
async function linkAll(db) {
  const log = makeLogger('LINKER');
  log.info('Starting cross-source linking pass…');

  // Build a lookup: technique_id string → DB row id
  const techRows = await db('techniques').select('id', 'technique_id');
  const techMap  = new Map(techRows.map(t => [t.technique_id, t.id]));
  log.info(`Loaded ${techMap.size} techniques into lookup map`);

  let cveLinks = 0;
  let iocLinks = 0;

  // ── 1. Link CVEs → techniques ─────────────────────────────────────────────
  // Scan CVE descriptions for technique IDs and keywords.
  // Process in batches to avoid loading millions of CVEs into memory.
  log.info('Linking CVEs to techniques…');
  const CVE_BATCH = 500;
  // BUG FIX: OFFSET pagination without an ORDER BY is non-deterministic in
  // Postgres (rows can be skipped or seen twice). Use keyset pagination on id.
  let lastCveId = 0;

  while (true) {
    const cves = await db('cves')
      .select('id', 'cve_id', 'description')
      .where('id', '>', lastCveId)
      .orderBy('id')
      .limit(CVE_BATCH);

    if (!cves.length) break;
    lastCveId = cves[cves.length - 1].id;

    const mappings = [];
    for (const cve of cves) {
      // A CVE description can reference several techniques — link them all.
      for (const m of findTechniques(cve.description, techMap)) {
        mappings.push({
          cve_id:           cve.id,
          technique_id:     m.dbId,
          confidence_score: m.confidence,
          source:           m.source,
        });
      }
    }

    if (mappings.length) {
      // ON CONFLICT DO NOTHING — don't overwrite manually curated links
      await db('cve_technique_map')
        .insert(mappings)
        .onConflict(['cve_id', 'technique_id'])
        .ignore();
      cveLinks += mappings.length;
    }

    if (cves.length < CVE_BATCH) break;
  }

  log.info(`CVE linking: ${cveLinks} mappings created`);

  // ── 2. Link IOCs → techniques ─────────────────────────────────────────────
  // Match IOC malware_family and tags fields against keyword map.
  log.info('Linking IOCs to techniques…');
  const IOC_BATCH = 1000;
  // BUG FIX: the old loop combined `whereNull('linked_technique_id')` with an
  // advancing OFFSET while simultaneously UPDATE-ing rows out of that filter,
  // so the result set shrank underneath the pagination and large swathes of
  // IOCs were never processed (the heatmap intensities came out far too low).
  // Keyset pagination on id is immune to this.
  let lastIocId = 0;

  while (true) {
    const iocs = await db('iocs')
      .select('id', 'malware_family', 'tags', 'threat_type')
      .whereNull('linked_technique_id')   // only unlinked IOCs
      .where('id', '>', lastIocId)
      .orderBy('id')
      .limit(IOC_BATCH);

    if (!iocs.length) break;
    lastIocId = iocs[iocs.length - 1].id;

    // Group ids per technique so each batch issues a handful of UPDATEs
    // instead of one round-trip per IOC.
    const byTechnique = new Map();

    for (const ioc of iocs) {
      // Build a single searchable string from all metadata fields
      const tags = Array.isArray(ioc.tags)
        ? ioc.tags.join(' ')
        : (typeof ioc.tags === 'string' ? ioc.tags : '');

      const raw = [ioc.malware_family, ioc.threat_type, tags].filter(Boolean).join(' ');
      // Search the raw text AND a normalized copy so "CobaltStrike" / "botnet_cc"
      // still match the spaced keywords in the map.
      const searchText = raw + ' ' + normalizeMeta(raw);

      const best = findBestTechnique(searchText, techMap);
      if (!best) continue;

      if (!byTechnique.has(best.dbId)) byTechnique.set(best.dbId, []);
      byTechnique.get(best.dbId).push(ioc.id);
    }

    for (const [techniqueDbId, ids] of byTechnique) {
      await db('iocs')
        .whereIn('id', ids)
        .update({ linked_technique_id: techniqueDbId, updated_at: new Date() });
      iocLinks += ids.length;
    }

    if (iocs.length < IOC_BATCH) break;
  }

  log.done(`Linking complete — ${cveLinks} CVE→technique links, ${iocLinks} IOC→technique links`);
  return { cveLinks, iocLinks };
}

module.exports = { linkAll, findTechniques, findBestTechnique, resolveTechnique, normalizeMeta };
