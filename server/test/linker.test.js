const test = require('node:test');
const assert = require('node:assert/strict');
const { findTechniques, findBestTechnique, resolveTechnique, normalizeMeta } = require('../src/ingestion/sources/linker');

// technique_id -> fake DB id; T1059.001 is deliberately missing to test the parent fallback.
const techMap = new Map([
  ['T1190', 1], ['T1059', 2], ['T1003', 3], ['T1486', 4], ['T1071', 5], ['T1203', 6], ['T1566', 7],
]);
const ids = list => list.map(m => m.technique_id).sort();

test('short keywords only match whole words ("rce" is not in "force")', () => {
  assert.deepEqual(findTechniques('A brute force issue in the resource manager', techMap)
    .filter(m => m.technique_id === 'T1190'), []);
  assert.deepEqual(ids(findTechniques('Unauthenticated RCE in the login form', techMap)), ['T1190']);
});

test('"c2" does not match "ec2"', () => {
  assert.deepEqual(findTechniques('Misconfigured AWS EC2 metadata endpoint', techMap), []);
});

test('explicit technique IDs win with higher confidence', () => {
  const [first] = findTechniques('Maps to T1003 per the advisory; uses mimikatz', techMap);
  assert.equal(first.technique_id, 'T1003');
  assert.equal(first.confidence, 0.9);
});

test('a missing sub-technique falls back to its parent', () => {
  assert.deepEqual(resolveTechnique('T1059.001', techMap), { dbId: 2, resolved: 'T1059' });
  assert.equal(resolveTechnique('T9999', techMap), null);
});

test('a CVE description can link several techniques, capped at 4', () => {
  const found = findTechniques('Phishing leads to a use-after-free, then command injection and ransomware deployment', techMap);
  assert.ok(found.length >= 3 && found.length <= 4);
});

test('malware family names are normalised before matching', () => {
  assert.equal(normalizeMeta('CobaltStrike botnet_cc'), 'Cobalt Strike botnet cc');
  const raw = 'CobaltStrike';
  assert.equal(findBestTechnique(`${raw} ${normalizeMeta(raw)}`, techMap).technique_id, 'T1071');
});
