const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeIocType, refang } = require('../src/lib/indicators');

test('normalizeIocType merges each feed\'s spelling of the same type', () => {
  assert.equal(normalizeIocType('sha1_hash'), 'sha1');      // ThreatFox
  assert.equal(normalizeIocType('FileHash-SHA1'), 'sha1');  // OTX
  assert.equal(normalizeIocType('sha1'), 'sha1');
  assert.equal(normalizeIocType('sha256_hash'), 'sha256');
  assert.equal(normalizeIocType('FileHash-MD5'), 'md5');
  assert.equal(normalizeIocType('ip:port'), 'ip');
  assert.equal(normalizeIocType('IPv6'), 'ip');
  assert.equal(normalizeIocType('hostname'), 'domain');
  assert.equal(normalizeIocType('URI'), 'url');
});

test('normalizeIocType keeps unknown types visible instead of dropping them', () => {
  assert.equal(normalizeIocType('JA3'), 'ja3');
  assert.equal(normalizeIocType(undefined), 'unknown');
});

test('refang restores defanged indicators', () => {
  assert.equal(refang('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.equal(refang('hxxp://evil(dot)com/x'), 'http://evil.com/x');
  assert.equal(refang('hxxps://a[.]b'), 'https://a.b');
  assert.equal(refang('  user[@]mail[.]com '), 'user@mail.com');
});
