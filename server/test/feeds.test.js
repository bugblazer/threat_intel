const test = require('node:test');
const assert = require('node:assert/strict');
const { parseCve } = require('../src/ingestion/sources/nvd');
const { parseKevEntry } = require('../src/ingestion/sources/kev');

test('a CVE NVD hasn\'t analysed yet has no score and no severity', () => {
  const row = parseCve({ cve: { id: 'CVE-2026-0001', descriptions: [{ lang: 'en', value: 'x' }], metrics: {} } });
  assert.equal(row.cvss_score, null);
  assert.equal(row.severity, null);
});

test('CVSS v3.1 is preferred and severity is uppercased', () => {
  const row = parseCve({ cve: { id: 'CVE-2026-0002', metrics: {
    cvssMetricV2:  [{ cvssData: { baseScore: 5, version: '2.0' }, baseSeverity: 'MEDIUM' }],
    cvssMetricV31: [{ cvssData: { baseScore: 9.8, version: '3.1', baseSeverity: 'critical' } }],
  } } });
  assert.equal(row.cvss_score, 9.8);
  assert.equal(row.severity, 'CRITICAL');
});

test('KEV entries map to the stored columns', () => {
  assert.deepEqual(parseKevEntry({
    cveID: 'CVE-2024-3400', dateAdded: '2024-04-12', dueDate: '2024-04-19', knownRansomwareCampaignUse: 'Known',
  }), { cve_id: 'CVE-2024-3400', kev_added_at: '2024-04-12', kev_due_date: '2024-04-19', kev_ransomware: true });
  assert.equal(parseKevEntry({ cveID: 'CVE-2024-1', knownRansomwareCampaignUse: 'Unknown' }), null);
  assert.equal(parseKevEntry({ cveID: 'CVE-2024-12345', knownRansomwareCampaignUse: 'Unknown' }).kev_ransomware, false);
});
