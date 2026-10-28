// The comparison of two readings: one event per transition, never at the
// first reading, never across a new address or a new source.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectTarget,
  memoryOf,
  TRIGGERS,
  MAX_EVENTS_PER_KIND,
  summaryText,
} from '../src/events.js';
import { parseInternetDb } from '../src/parse.js';

const reading = (values, ip = '203.0.113.7') =>
  parseInternetDb({ ip, ports: [], vulns: [], tags: [], ...values }, ip);

test('first reading: a baseline, no event', () => {
  const { events, next } = detectTarget(undefined, reading({ ports: [22] }));
  assert.deepEqual(events, []);
  assert.deepEqual(next.ports, [22]);
});

test('ports, CVE and tags added or gone', () => {
  const seen = memoryOf(reading({ ports: [22, 80], vulns: ['CVE-2020-0001'], tags: ['vpn'] }));
  const { events } = detectTarget(
    seen,
    reading({ ports: [22, 443], vulns: ['CVE-2021-0002'], tags: ['vpn', 'compromised'] }),
  );
  assert.deepEqual(
    events.map((event) => [event.key, Object.values(event.values)[0]]),
    [
      [TRIGGERS.PORT_OPENED, 443],
      [TRIGGERS.PORT_CLOSED, 80],
      [TRIGGERS.VULNERABILITY_FOUND, 'CVE-2021-0002'],
      [TRIGGERS.VULNERABILITY_GONE, 'CVE-2020-0001'],
      [TRIGGERS.TAG_ADDED, 'compromised'],
    ],
  );
});

test('a new address or a new source: a new baseline', () => {
  const seen = memoryOf(reading({ ports: [22] }));
  assert.deepEqual(detectTarget(seen, reading({ ports: [8080] }, '198.51.100.20')).events, []);
  assert.deepEqual(detectTarget(seen, { ...reading({ ports: [8080] }), source: 'api' }).events, []);
});

test('so many events per kind at most', () => {
  const seen = memoryOf(reading({ ports: [] }));
  const ports = Array.from({ length: 30 }, (_, i) => 8000 + i);
  assert.equal(detectTarget(seen, reading({ ports })).events.length, MAX_EVENTS_PER_KIND);
});

test('the summary of a reading, for a message', () => {
  assert.equal(summaryText(reading({}), 'fr'), '203.0.113.7 : Shodan ne voit aucun port ouvert.');
  assert.equal(
    summaryText(reading({ ports: [443] }), 'en', 'Home'),
    'Home (203.0.113.7): 1 open port (443), no known vulnerability.',
  );
});
