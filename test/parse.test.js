// The answers of Shodan made safe, and the addresses typed by the user.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseInternetDb,
  parseHost,
  parseApiInfo,
  notFound,
  maxCvss,
  portsText,
  isPublicIp,
  parseAddresses,
  shodanTime,
} from '../src/parse.js';

const hosts = JSON.parse(readFileSync(new URL('./fixtures/hosts.json', import.meta.url), 'utf8'));

test('InternetDB: ports sorted, CVE upper case, no service, no score', () => {
  const reading = parseInternetDb(hosts.internetdb['203.0.113.7'], '203.0.113.7');
  assert.equal(reading.source, 'internetdb');
  assert.equal(reading.found, true);
  assert.deepEqual(reading.ports, [22, 443]);
  assert.deepEqual(reading.vulns, ['CVE-2021-23017', 'CVE-2023-38408']);
  assert.deepEqual(reading.tags, ['self-signed']);
  assert.deepEqual(reading.services, []);
  assert.equal(maxCvss(reading), null);
  assert.equal(portsText(reading), '22, 443');
  const odd = parseInternetDb(
    { ports: [80, '80', 0, 70000, 'x'], vulns: ['cve-2020-1234', 'nope', 'CVE-2020-1234'] },
    '198.51.100.1',
  );
  assert.deepEqual(odd.ports, [80]);
  assert.deepEqual(odd.vulns, ['CVE-2020-1234']);
  assert.equal(odd.ip, '198.51.100.1');
});

test('API host: services with product and version, CVSS per CVE, last update in UTC', () => {
  const reading = parseHost(hosts.api['203.0.113.7'], '203.0.113.7');
  assert.equal(reading.source, 'api');
  assert.deepEqual(reading.ports, [22, 443]);
  assert.deepEqual(
    reading.services.map(({ port, transport, product }) => [port, transport, product]),
    [
      [22, 'tcp', 'OpenSSH'],
      [443, 'tcp', 'nginx'],
    ],
  );
  assert.deepEqual(reading.cvss, { 'CVE-2023-38408': 9.8, 'CVE-2021-23017': 7.7 });
  assert.equal(maxCvss(reading), 9.8);
  assert.match(reading.summaries['CVE-2023-38408'], /^The PKCS#11/);
  assert.equal(reading.lastUpdate, Date.parse('2026-10-26T04:12:33.481Z'));
  assert.equal(reading.org, 'Example Telecom');
  assert.equal(portsText(reading), '22/tcp, 443/tcp');
  assert.deepEqual(parseHost({}, '198.51.100.1').ports, []);
});

test('nothing known is a reading without ports, never an error', () => {
  const reading = notFound('198.51.100.9', 'internetdb');
  assert.equal(reading.found, false);
  assert.deepEqual([reading.ports, reading.vulns], [[], []]);
});

test('api-info: plan, credits and limits; absent is null', () => {
  assert.deepEqual(parseApiInfo(hosts.apiInfo), {
    plan: 'dev',
    queryCredits: 100,
    scanCredits: 87,
    monitoredIps: 3,
    limits: { queryCredits: 100, scanCredits: 100, monitoredIps: 16 },
  });
  assert.equal(parseApiInfo({}).scanCredits, null);
});

test('times of Shodan: UTC without a zone, microseconds cut', () => {
  assert.equal(shodanTime('2026-10-26T04:12:33.481920'), Date.parse('2026-10-26T04:12:33.481Z'));
  assert.equal(shodanTime('2026-10-26T04:12:33Z'), Date.parse('2026-10-26T04:12:33Z'));
  assert.equal(shodanTime('soon'), null);
});

test('public addresses only: private, loopback, shared, reserved and documentation ones are not', () => {
  for (const ip of ['203.0.113.7', '82.66.249.84', '2a01:e0a:1:2::3']) {
    assert.ok(isPublicIp(ip), ip);
  }
  for (const ip of [
    '10.0.0.1',
    '192.168.1.1',
    '172.20.0.1',
    '127.0.0.1',
    '169.254.1.1',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    'fe80::1',
    'fd00::1',
    '2001:db8::1',
    '::ffff:192.168.1.1',
    'home',
  ]) {
    assert.ok(!isPublicIp(ip), ip);
  }
});

test('addresses typed: IPs and host names, lower case, without duplicates, 10 at most', () => {
  const { addresses, rejected } = parseAddresses(
    'Home.Example.org, 198.51.100.20;192.168.1.1\nhome.example.org nas.local box not_a_host!',
  );
  assert.deepEqual(addresses, [
    { address: 'home.example.org', kind: 'host' },
    { address: '198.51.100.20', kind: 'ip' },
  ]);
  assert.deepEqual(rejected, ['192.168.1.1', 'nas.local', 'box', 'not_a_host!']);
  const many = Array.from({ length: 14 }, (_, i) => `198.51.100.${i + 1}`).join(',');
  assert.equal(parseAddresses(many).addresses.length, 10);
  assert.deepEqual(parseAddresses(undefined), { addresses: [], rejected: [] });
});
