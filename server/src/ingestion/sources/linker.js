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

  // Malware families → their primary technique
  { keywords: ['emotet'],                              technique: 'T1566' },
  { keywords: ['trickbot'],                            technique: 'T1055' },
  { keywords: ['qbot', 'qakbot'],                     technique: 'T1566' },
  { keywords: ['lockbit'],                             technique: 'T1486' },
  { keywords: ['conti'],                               technique: 'T1486' },
  { keywords: ['ryuk'],                                technique: 'T1486' },
  { keywords: ['wannacry', 'notpetya'],                technique: 'T1486' },
  { keywords: ['metasploit', 'meterpreter'],           technique: 'T1059' },
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
 * Find the best matching technique_id for a block of text.
 * Returns the technique_id string (e.g. "T1059.001") or null.
 * @param {string} text
 * @param {Map}    [techMap] - known technique_id → db id. When provided,
 *   explicit IDs not present in the map are skipped so we can still fall
 *   back to keyword matching instead of dropping the row.
 */
function findTechniqueForText(text, techMap) {
  if (!text) return null;

  // 1. Explicit T#### ID in the text — most reliable
  for (const id of text.match(TECHNIQUE_ID_REGEX) ?? []) {
    if (!techMap || techMap.has(id)) return id;
  }

  // 2. Keyword match — first hit wins (map is ordered most→least specific)
  for (const { regexes, technique } of COMPILED_KEYWORD_MAP) {
    if (regexes.some(re => re.test(text))) return technique;
  }

  return null;
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
      const techId = findTechniqueForText(cve.description, techMap);
      if (!techId) continue;

      const techniqueDbId = techMap.get(techId);
      if (!techniqueDbId) continue;

      mappings.push({
        cve_id:           cve.id,
        technique_id:     techniqueDbId,
        confidence_score: 0.60,  // keyword match — moderate confidence
        source:           'auto-keyword',
      });
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

      const searchText = [ioc.malware_family, ioc.threat_type, tags]
        .filter(Boolean)
        .join(' ');

      const techId = findTechniqueForText(searchText, techMap);
      if (!techId) continue;

      const techniqueDbId = techMap.get(techId);
      if (!techniqueDbId) continue;

      if (!byTechnique.has(techniqueDbId)) byTechnique.set(techniqueDbId, []);
      byTechnique.get(techniqueDbId).push(ioc.id);
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

module.exports = { linkAll };
