// The HTTP client of Shodan, against the fake Shodan (no network).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createShodanClient, retryAfterSeconds, SPACING_MS } from '../src/shodan-api.js';
import { createFakeShodan, KEY } from './helpers/fake-shodan.js';

const NOW = Date.parse('2026-10-28T09:00:00Z');

/**
 * @description A client on the fake Shodan.
 * @param {object} [options] - `{ key }`.
 * @returns {{ client: object, fake: object, clock: object }} The client.
 */
function setup({ key = KEY } = {}) {
  const clock = { now: NOW };
  const fake = createFakeShodan({ clock });
  const client = createShodanClient({
    getKey: () => key,
    userAgent: 'gladys-shodan/test',
    fetch: (url, init) => fake.fetch(url, init),
    apiUrl: fake.apiUrl,
    internetDbUrl: fake.internetDbUrl,
    now: () => clock.now,
    sleep: async (ms) => {
      clock.now += ms;
    },
  });
  return { client, fake, clock };
}

test('InternetDB without a key, the API with it, 1.1 s apart, with the User-Agent', async () => {
  const { client, fake } = setup();
  assert.deepEqual((await client.internetDb('203.0.113.7')).ports, [443, 22]);
  assert.equal((await client.host('203.0.113.7')).ip_str, '203.0.113.7');
  assert.equal(await client.myIp(), '203.0.113.7');
  const [internetdb, host] = fake.calls;
  assert.equal(internetdb.key, null, 'InternetDB never gets the key');
  assert.equal(host.key, KEY);
  assert.ok(host.at - internetdb.at >= SPACING_MS);
  assert.equal(host.userAgent, 'gladys-shodan/test');
});

test('the public address is asked without a key when there is none', async () => {
  const { client, fake } = setup({ key: '' });
  assert.equal(await client.myIp(), '203.0.113.7');
  assert.equal(fake.calls[0].key, null);
  await assert.rejects(client.host('203.0.113.7'), { kind: 'auth', code: 'missing' });
  assert.equal(fake.callsTo(/^\/shodan\/host\//).length, 0, 'no request without a key');
});

test('errors: key refused, plan, nothing known, invalid address; the key is never in them', async () => {
  const { client, fake } = setup({ key: 'wrong-key' });
  const refused = await client.host('203.0.113.7').catch((err) => err);
  assert.equal(refused.kind, 'auth');
  assert.equal(refused.status, 401);
  assert.doesNotMatch(JSON.stringify({ ...refused, message: refused.message }), /wrong-key/);
  const ok = setup();
  await assert.rejects(ok.client.host('198.51.100.99'), { kind: 'not_found' });
  await assert.rejects(ok.client.host('192.168.1.1'), { kind: 'invalid' });
  await assert.rejects(ok.client.internetDb('198.51.100.99'), { kind: 'not_found' });
  ok.fake.planDenied = true;
  await assert.rejects(ok.client.host('203.0.113.7'), { kind: 'plan', status: 403 });
  assert.equal(fake.calls.length, 1);
});

test('a 429 or no answer pauses that service only', async () => {
  const { client, fake, clock } = setup();
  fake.rateLimited.add('internetdb');
  await assert.rejects(client.internetDb('203.0.113.7'), { kind: 'rate_limit', status: 429 });
  await assert.rejects(client.internetDb('203.0.113.7'), { kind: 'rate_limit', message: /paused/ });
  assert.equal(fake.callsTo('/203.0.113.7').length, 1, 'paused: no second request');
  assert.ok(client.pausedUntil('internetdb') > clock.now);
  assert.equal(client.pausedUntil('api'), 0);
  assert.ok(await client.host('203.0.113.7'));
  fake.down.add('api');
  const err = await client.myIp().catch((error) => error);
  assert.equal(err.kind, 'unreachable');
  assert.doesNotMatch(err.message, new RegExp(KEY));
  fake.rateLimited.clear();
  clock.now += 3 * 60 * 60 * 1000;
  assert.equal(client.pausedUntil(), 0);
  assert.ok(await client.internetDb('203.0.113.7'));
});

test('scan: form ips, credits left, then its status', async () => {
  const { client, fake } = setup();
  const answer = await client.scan('203.0.113.7');
  assert.deepEqual(answer, { id: 'SCAN1', count: 1, credits_left: 86 });
  assert.equal(fake.callsTo('/shodan/scan')[0].body, 'ips=203.0.113.7');
  assert.equal((await client.scanStatus('SCAN1')).status, 'QUEUE');
  assert.equal((await client.apiInfo()).plan, 'dev');
});

test('Retry-After: seconds or an HTTP date', () => {
  assert.equal(retryAfterSeconds('120', NOW), 120);
  assert.equal(retryAfterSeconds(new Date(NOW + 30000).toUTCString(), NOW), 30);
  assert.equal(retryAfterSeconds(null, NOW), null);
});
