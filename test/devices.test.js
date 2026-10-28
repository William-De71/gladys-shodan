// The devices offered on the Discovery screen, checked like the core checks
// them (a single invalid field rejects the whole batch, and a missing min /
// max / read_only / has_feedback makes "Add" fail in 422).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  DEVICE_FEATURE_CATEGORIES as C,
  DEVICE_FEATURE_TYPES as T,
} from '@gladysassistant/integration-sdk';
import { parseInternetDb, parseHost } from '../src/parse.js';
import {
  buildTargetDevice,
  buildTargetStates,
  targetOfExternalId,
  platformId,
  PUBLIC_ID,
} from '../src/device.js';
import { LANGUAGES } from '../src/i18n.js';

const fakeGladys = {
  externalIds: (type, id) => ({
    device: `ext:test-integration:${type}:${id}`,
    feature: (key) => `ext:test-integration:${type}:${id}:${key}`,
  }),
};
const hosts = JSON.parse(readFileSync(new URL('./fixtures/hosts.json', import.meta.url), 'utf8'));
const PUBLIC = { id: PUBLIC_ID, kind: 'public', address: null };
const HOST = { id: 'home.example.org', kind: 'host', address: 'home.example.org' };
const IPV6 = { id: '2a01:e0a:1:2::3', kind: 'ip', address: '2a01:e0a:1:2::3' };

// The pairs of the core (DEVICE_FEATURE_UNITS_BY_CATEGORY, master 2026-10-26).
const TYPES_OF = {
  [C.COUNTER_SENSOR]: [T.SENSOR.INTEGER],
  [C.TEXT]: [T.TEXT.TEXT],
};

test('every feature is complete, read only, on a pair of the core, in every language', () => {
  for (const language of LANGUAGES) {
    for (const target of [PUBLIC, HOST, IPV6]) {
      const device = buildTargetDevice(fakeGladys, target, { language });
      assert.equal(device.should_poll, false);
      assert.equal(device.poll_frequency, undefined, 'its own timer');
      assert.ok(device.name.length <= 100);
      for (const feature of device.features) {
        for (const key of ['min', 'max', 'read_only', 'has_feedback']) {
          assert.notEqual(feature[key], undefined, `${feature.external_id}.${key}`);
        }
        assert.equal(feature.read_only, true);
        assert.ok(TYPES_OF[feature.category]?.includes(feature.type), feature.external_id);
        assert.equal(feature.unit, null);
        assert.ok(feature.name.trim(), `${feature.external_id} ${language}`);
      }
    }
  }
});

test('external ids: the public address keeps one device; an address is made safe', () => {
  assert.equal(
    buildTargetDevice(fakeGladys, PUBLIC).external_id,
    'ext:test-integration:target:public',
  );
  assert.equal(platformId(HOST), 'home-example-org');
  assert.equal(platformId(IPV6), '2a01-e0a-1-2--3');
  assert.equal(
    targetOfExternalId('ext:sel:target:home-example-org:open_ports'),
    'home-example-org',
  );
  assert.equal(targetOfExternalId('ext:sel:target:public'), 'public');
  assert.equal(targetOfExternalId('nope'), null);
  assert.deepEqual(
    LANGUAGES.map((language) => buildTargetDevice(fakeGladys, PUBLIC, { language }).name),
    ['Shodan: public IP', 'Shodan : IP publique', 'Shodan: öffentliche IP', 'Shodan: IP pública'],
  );
});

test('states: counts, the address, the ports; nothing before a reading', () => {
  const internetdb = parseInternetDb(hosts.internetdb['203.0.113.7'], '203.0.113.7');
  const states = buildTargetStates(fakeGladys, PUBLIC, internetdb);
  assert.deepEqual(
    states.map((state) => [
      state.device_feature_external_id.split(':').pop(),
      state.state ?? state.text,
    ]),
    [
      ['open_ports', 2],
      ['vulnerabilities', 2],
      ['ip', '203.0.113.7'],
      ['ports', '22, 443'],
    ],
  );
  const api = parseHost(hosts.api['203.0.113.7'], '203.0.113.7');
  assert.equal(buildTargetStates(fakeGladys, PUBLIC, api)[3].text, '22/tcp, 443/tcp');
  const empty = parseInternetDb({ ip: '198.51.100.9' }, '198.51.100.9');
  assert.equal(
    buildTargetStates(fakeGladys, PUBLIC, empty, { language: 'fr' })[3].text,
    'aucun vu',
  );
  assert.deepEqual(buildTargetStates(fakeGladys, PUBLIC, null), []);
});
