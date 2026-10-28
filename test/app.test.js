// The whole integration against the fake Gladys of the SDK
// (`@gladysassistant/integration-sdk/testing`), which checks the discovered
// devices, the states and the scene events like the host API does, and a fake
// Shodan (test/helpers/fake-shodan.js), an in-memory fetch on a fake clock.
// No test touches the network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createFakeGladys } from '@gladysassistant/integration-sdk/testing';
import { validateWidgetContent } from '@gladysassistant/integration-sdk';

import { createApp, ACTIONS, USER_AGENT, KEY_RETRY_MS } from '../src/app.js';
import { WIDGETS, WIDGET_ACTIONS } from '../src/widgets.js';
import { TRIGGERS, SCENE_ACTIONS, TARGET_OUTPUTS, LOOKUP_OUTPUTS } from '../src/events.js';
import { FILE } from '../src/store.js';
import { LANGUAGES } from '../src/i18n.js';
import { createFakeShodan, dataDir, recordingLogger, KEY } from './helpers/fake-shodan.js';

const NOW = Date.parse('2026-10-28T09:00:00Z');
const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const CONFIG = { monitor_public_ip: true, addresses: '', language: 'en' };
const PREFIX = 'ext:test-integration';
const HOME = '203.0.113.7';
const id = (target, feature) => `${PREFIX}:target:${target}${feature ? `:${feature}` : ''}`;

/**
 * @description The integration, connected to a fake Gladys and a fake Shodan.
 * @param {object} t - The test context.
 * @param {object} [options] - `{ config, dir, clock, fake, resolve }`.
 * @returns {Promise<object>} `{ gladys, app, fake, clock, dir, logger }`.
 */
async function startApp(
  t,
  { config = CONFIG, dir = dataDir(), clock = { now: NOW }, fake, resolve } = {},
) {
  fake ??= createFakeShodan({ clock });
  fake.clock = clock;
  const logger = recordingLogger();
  const gladys = createFakeGladys({ config });
  const app = createApp(gladys, {
    fetch: (url, init) => fake.fetch(url, init),
    apiUrl: fake.apiUrl,
    internetDbUrl: fake.internetDbUrl,
    resolve:
      resolve ??
      (async (host) => {
        if (host === 'home.example.org') return ['2a01:e0a:1:2::3', HOME];
        if (host === 'lan.example.org') return ['192.168.1.20'];
        throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
      }),
    dataDir: dir,
    now: () => clock.now,
    sleep: async (ms) => {
      clock.now += ms;
    },
    timeZone: 'Europe/Paris',
    timers: false,
    logger,
  });
  await gladys.connect();
  await app.whenReady();
  t.after(async () => {
    await gladys.fake.shutdown().catch(() => {});
  });
  return { gladys, app, fake, clock, dir, logger };
}

/**
 * @description Run the timer like the real one (every minute) for a while.
 * @param {object} env - `{ app, clock }`.
 * @param {number} ms - How long.
 */
async function run({ app, clock }, ms) {
  const end = clock.now + ms;
  while (clock.now < end) {
    await app.tick();
    clock.now += MINUTE;
  }
}

/**
 * @description Create every offered device, like the user would.
 * @param {object} gladys - The fake Gladys.
 */
async function createAll(gladys) {
  for (const device of gladys.fake.discoveredDevices) {
    await gladys.fake.deviceCreated(structuredClone(device));
  }
}
const widget = async (gladys, key, options) =>
  (await gladys.fake.widgetGet(key, options)).data.content;
const events = (gladys, key) => gladys.fake.sceneEvents.filter((event) => event.key === key);
const lastState = (gladys, featureId) =>
  gladys.fake.states.filter((state) => state.device_feature_external_id === featureId).at(-1);

test('startup without a key: the public address, then InternetDB; one device per address', async (t) => {
  const env = await startApp(t, {
    config: { ...CONFIG, addresses: 'home.example.org, 198.51.100.20' },
  });
  const { gladys, fake } = env;
  assert.deepEqual(fake.calls, [], 'no request before the timer');
  await run(env, 2 * MINUTE);
  assert.deepEqual(
    fake.calls.map((call) => `${call.service} ${call.path}`),
    ['api /tools/myip', `internetdb /${HOME}`, `internetdb /${HOME}`, 'internetdb /198.51.100.20'],
  );
  assert.equal(fake.calls[0].userAgent, USER_AGENT);
  assert.ok(
    fake.calls.every((call) => call.key === null),
    'no key anywhere',
  );
  assert.deepEqual(
    gladys.fake.discoveredDevices.map((device) => [
      device.name,
      device.external_id,
      device.should_poll,
      device.features.map((feature) => feature.external_id.split(':').pop()),
    ]),
    [
      ['Shodan: public IP', id('public'), false, ['open_ports', 'vulnerabilities', 'ip', 'ports']],
      [
        'Shodan home.example.org',
        id('home-example-org'),
        false,
        ['open_ports', 'vulnerabilities', 'ip', 'ports'],
      ],
      [
        'Shodan 198.51.100.20',
        id('198-51-100-20'),
        false,
        ['open_ports', 'vulnerabilities', 'ip', 'ports'],
      ],
    ],
  );
  assert.deepEqual(gladys.fake.connectionStatus, {
    connected: true,
    message: {
      en: '3 addresses watched: 5 open port(s), 4 vulnerability(ies).',
      fr: '3 adresses surveillées : 5 port(s) ouvert(s), 4 vulnérabilité(s).',
      de: '3 Adressen überwacht: 5 offene(r) Port(s), 4 Schwachstelle(n).',
      es: '3 direcciones vigiladas: 5 puerto(s) abierto(s), 4 vulnerabilidad(es).',
    },
  });
  assert.deepEqual(gladys.fake.states, [], 'no state before the devices exist');
  assert.deepEqual(gladys.fake.sceneEvents, [], 'never at the first reading');
  await createAll(gladys);
  assert.equal(lastState(gladys, id('public', 'open_ports')).state, 2);
  assert.equal(lastState(gladys, id('public', 'vulnerabilities')).state, 2);
  assert.equal(lastState(gladys, id('public', 'ip')).text, HOME);
  assert.equal(lastState(gladys, id('public', 'ports')).text, '22, 443');
  assert.equal(lastState(gladys, id('198-51-100-20', 'ports')).text, '8443');
  const mode = statSync(join(env.dir, FILE)).mode & 0o777;
  assert.equal(mode, 0o600);
});

test('pace: the public address every 15 minutes, each address every 6 hours', async (t) => {
  const env = await startApp(t);
  await run(env, 24 * HOUR);
  const myip = env.fake.callsTo('/tools/myip').length;
  assert.ok(myip >= 96 && myip <= 98, `${myip} checks of the public address`);
  const reads = env.fake.callsTo(`/${HOME}`).map((call) => call.at);
  assert.equal(reads.length, 4);
  for (let i = 1; i < reads.length; i += 1) {
    assert.ok(reads[i] - reads[i - 1] >= 6 * HOUR);
  }
});

test('triggers: port opened and closed, CVE found and gone, tag added, with their data', async (t) => {
  const env = await startApp(t);
  const { gladys, fake } = env;
  await run(env, 2 * MINUTE);
  await createAll(gladys);
  fake.internetdb[HOME] = {
    ...fake.internetdb[HOME],
    ports: [22, 443, 8123],
    vulns: ['CVE-2023-38408', 'CVE-2024-6387'],
    tags: ['self-signed', 'compromised'],
  };
  await run(env, 6 * HOUR);
  const [opened] = events(gladys, TRIGGERS.PORT_OPENED);
  assert.deepEqual(opened.data, {
    target: id('public'),
    target_name: 'Shodan: public IP',
    ip: HOME,
    ports: '22, 443, 8123',
    port: 8123,
    transport: null,
    product: null,
  });
  assert.equal(events(gladys, TRIGGERS.VULNERABILITY_FOUND)[0].data.cve, 'CVE-2024-6387');
  assert.equal(
    events(gladys, TRIGGERS.VULNERABILITY_FOUND)[0].data.url,
    'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
  );
  assert.equal(events(gladys, TRIGGERS.VULNERABILITY_GONE)[0].data.cve, 'CVE-2021-23017');
  assert.equal(events(gladys, TRIGGERS.TAG_ADDED)[0].data.tag, 'compromised');
  assert.equal(events(gladys, TRIGGERS.PORT_CLOSED).length, 0);
  assert.equal(lastState(gladys, id('public', 'open_ports')).state, 3);
  fake.internetdb[HOME] = { ...fake.internetdb[HOME], ports: [443] };
  await run(env, 6 * HOUR);
  assert.deepEqual(
    events(gladys, TRIGGERS.PORT_CLOSED).map((event) => event.data.port),
    [22, 8123],
  );
  // Once per transition: nothing more while nothing changes.
  const count = gladys.fake.sceneEvents.length;
  await run(env, 12 * HOUR);
  assert.equal(gladys.fake.sceneEvents.length, count);
});

test('a new public address: the trigger, a new baseline without port events', async (t) => {
  const env = await startApp(t);
  const { gladys, fake } = env;
  await run(env, 2 * MINUTE);
  fake.publicIp = '198.51.100.20';
  await run(env, 20 * MINUTE);
  assert.deepEqual(
    events(gladys, TRIGGERS.PUBLIC_IP_CHANGED).map((event) => event.data),
    [{ previous_ip: HOME, ip: '198.51.100.20' }],
  );
  assert.equal(fake.callsTo('/198.51.100.20').length, 1, 'read at once');
  assert.equal(events(gladys, TRIGGERS.PORT_OPENED).length, 0);
  assert.equal(events(gladys, TRIGGERS.PORT_CLOSED).length, 0);
  assert.equal(env.app.viewOf(env.app.targets()[0], 'en').reading.ip, '198.51.100.20');
});

test('with a key: the API (services, CVSS, last scan), the credits; never the key in the logs', async (t) => {
  const env = await startApp(t, { config: { ...CONFIG, api_key: KEY } });
  const { gladys, fake, logger } = env;
  await run(env, 2 * MINUTE);
  assert.deepEqual(
    fake.calls.map((call) => `${call.service} ${call.path}`),
    ['api /tools/myip', `api /shodan/host/${HOME}`, 'api /api-info'],
  );
  await createAll(gladys);
  assert.equal(lastState(gladys, id('public', 'ports')).text, '22/tcp, 443/tcp');
  const content = await widget(gladys, WIDGETS.TARGET, { language: 'fr' });
  assert.deepEqual(validateWidgetContent(content).errors ?? [], []);
  const tiles = content.components.filter((component) => component.type === 'value');
  assert.deepEqual(
    tiles.map((tile) => [tile.label, tile.value]),
    [
      ['Ports ouverts', 2],
      ['Vulnérabilités', 2],
      ['CVSS maximal', '9,8'],
    ],
  );
  const cards = content.components.find((component) => component.type === 'card-list').items;
  assert.deepEqual(
    cards.map((card) => [card.title, card.subtitle, card.badge?.text]),
    [
      ['22/tcp', 'OpenSSH 8.9p1 Ubuntu-3ubuntu0.1', '1 CVE'],
      ['443/tcp', 'nginx 1.18.0', '1 CVE'],
    ],
  );
  const account = await widget(gladys, WIDGETS.ACCOUNT, { language: 'en' });
  assert.deepEqual(validateWidgetContent(account).errors ?? [], []);
  assert.equal(account.components[1].value, '87/100');
  const outputs = (await gladys.fake.sceneAction(SCENE_ACTIONS.GET_TARGET, {})).data.outputs;
  assert.equal(outputs.max_cvss, 9.8);
  assert.equal(outputs.last_scan, '2026-10-26T04:12:33.481Z');
  assert.equal(outputs.source, 'api');
  assert.equal(
    outputs.summary,
    'Shodan: public IP (203.0.113.7): 2 open ports (22/tcp, 443/tcp), 2 vulnerabilities (CVSS 9.8). Shodan tags: self-signed.',
  );
  assert.ok(Object.keys(outputs).every((key) => TARGET_OUTPUTS.includes(key)));
  await gladys.fake.action(ACTIONS.DIAGNOSTIC);
  assert.ok(logger.lines.some((line) => line.includes('Shodan diagnostic 1/')));
  assert.ok(!logger.lines.some((line) => line.includes(KEY)), 'the key is never logged');
  assert.ok(!readFileSync(join(env.dir, FILE), 'utf8').includes(KEY), 'never in /data');
});

test('a refused key: InternetDB answers, the trigger fires once, the key is tried again later', async (t) => {
  const env = await startApp(t, { config: { ...CONFIG, api_key: 'wrong-key' } });
  const { gladys, fake } = env;
  await run(env, 2 * MINUTE);
  assert.equal(fake.callsTo(`/shodan/host/${HOME}`).length, 1);
  assert.equal(fake.callsTo(`/${HOME}`).length, 1, 'InternetDB took over');
  assert.deepEqual(
    events(gladys, TRIGGERS.ACCESS_REFUSED).map((event) => event.data.reason),
    ['refused'],
  );
  assert.match(gladys.fake.connectionStatus.message.en, /API key refused: InternetDB/);
  assert.equal(gladys.fake.connectionStatus.connected, true);
  await run(env, KEY_RETRY_MS);
  assert.equal(events(gladys, TRIGGERS.ACCESS_REFUSED).length, 1, 'once per refusal');
  assert.ok(fake.callsTo(`/shodan/host/${HOME}`).length >= 2, 'tried again after 6 hours');
  // The right key: the API again, a new baseline without events.
  const before = gladys.fake.sceneEvents.length;
  await gladys.fake.configUpdated({ ...CONFIG, api_key: KEY });
  await run(env, 2 * MINUTE);
  assert.equal(env.app.viewOf(env.app.targets()[0], 'en').reading.source, 'api');
  assert.equal(gladys.fake.sceneEvents.length, before, 'a change of source is no event');
});

test('a plan without host lookups (403): InternetDB for a day', async (t) => {
  const clock = { now: NOW };
  const fake = createFakeShodan({ clock });
  fake.planDenied = true;
  const env = await startApp(t, { config: { ...CONFIG, api_key: KEY }, clock, fake });
  await run(env, 2 * MINUTE);
  assert.equal(env.app.viewOf(env.app.targets()[0], 'en').reading.source, 'internetdb');
  assert.equal(events(env.gladys, TRIGGERS.ACCESS_REFUSED).length, 0, 'the key itself is fine');
  await run(env, 12 * HOUR);
  assert.equal(fake.callsTo(`/shodan/host/${HOME}`).length, 1, 'not tried again for a day');
});

test('scene actions: look up any address, scan a watched one and follow the scan', async (t) => {
  const env = await startApp(t, { config: { ...CONFIG, api_key: KEY } });
  const { gladys, fake } = env;
  await run(env, 2 * MINUTE);
  const found = (
    await gladys.fake.sceneAction(SCENE_ACTIONS.LOOKUP_ADDRESS, { address: 'home.example.org' })
  ).data.outputs;
  assert.equal(found.ip, HOME, 'IPv4 first');
  assert.equal(found.found, true);
  assert.equal(found.vulns, 'CVE-2021-23017, CVE-2023-38408');
  assert.ok(Object.keys(found).every((key) => LOOKUP_OUTPUTS.includes(key)));
  const unknown = (
    await gladys.fake.sceneAction(SCENE_ACTIONS.LOOKUP_ADDRESS, { address: '198.51.100.99' })
  ).data.outputs;
  assert.deepEqual([unknown.found, unknown.port_count], [false, 0]);
  const lan = await gladys.fake.sceneAction(SCENE_ACTIONS.LOOKUP_ADDRESS, {
    address: '192.168.1.1',
  });
  assert.equal(lan.success, false);
  assert.match(lan.error, /is not a public IP address/);
  const resolved = await gladys.fake.sceneAction(SCENE_ACTIONS.LOOKUP_ADDRESS, {
    address: 'lan.example.org',
  });
  assert.match(resolved.error, /does not resolve to a public address/);
  const scan = (await gladys.fake.sceneAction(SCENE_ACTIONS.REQUEST_SCAN, {})).data.outputs;
  assert.deepEqual(scan, { scan_id: 'SCAN1', ip: HOME, credits_left: 86 });
  const reads = fake.callsTo(`/shodan/host/${HOME}`).length;
  fake.scans.get('SCAN1').status = 'DONE';
  await run(env, 4 * MINUTE);
  assert.equal(fake.callsTo(`/shodan/host/${HOME}`).length, reads + 1, 'read again once done');
  assert.equal(env.app.store.data.scans[0].status, 'DONE');
  assert.equal(gladys.fake.sceneEvents.length, 0, 'never an event from a scene action');
});

test('the scan needs a key; get_target needs a reading', async (t) => {
  const env = await startApp(t);
  const early = await env.gladys.fake.sceneAction(SCENE_ACTIONS.GET_TARGET, {});
  assert.equal(early.success, false);
  const scan = await env.gladys.fake.sceneAction(SCENE_ACTIONS.REQUEST_SCAN, {});
  assert.match(scan.error, /needs a Shodan API key/);
});

test('widgets: every content valid in the four languages; the button reads again', async (t) => {
  const env = await startApp(t, { config: { ...CONFIG, addresses: '198.51.100.20' } });
  const { gladys, fake } = env;
  await run(env, 2 * MINUTE);
  for (const language of LANGUAGES) {
    for (const key of Object.values(WIDGETS)) {
      const content = await widget(gladys, key, { language });
      assert.deepEqual(validateWidgetContent(content).errors ?? [], [], `${key} ${language}`);
    }
  }
  const overview = await widget(gladys, WIDGETS.OVERVIEW, { language: 'en' });
  const items = overview.components.find((component) => component.type === 'card-list').items;
  assert.deepEqual(
    items.map((item) => [item.title, item.badge.text]),
    [
      ['Shodan: public IP', '2 CVE'],
      ['Shodan 198.51.100.20', '1 port'],
    ],
  );
  const account = await widget(gladys, WIDGETS.ACCOUNT, { language: 'en' });
  assert.match(account.components[0].text, /needs a Shodan API key/);
  const content = await widget(gladys, WIDGETS.TARGET, {
    language: 'en',
    settings: { target: id('198-51-100-20') },
  });
  const button = content.components.find((component) => component.action);
  assert.deepEqual(button.action, {
    key: WIDGET_ACTIONS.REFRESH,
    params: { target: '198-51-100-20' },
  });
  const toast = await gladys.fake.widgetAction(
    WIDGETS.TARGET,
    WIDGET_ACTIONS.REFRESH,
    button.action.params,
  );
  assert.equal(toast.data.message.en, 'Read again: 1 port(s), 0 vulnerability(ies).');
  const soon = await gladys.fake.widgetAction(
    WIDGETS.TARGET,
    WIDGET_ACTIONS.REFRESH,
    button.action.params,
  );
  assert.match(soon.data.message.en, /less than a minute/);
  assert.equal(fake.callsTo('/198.51.100.20').length, 2);
  const link = content.components.find((component) => component.link);
  assert.equal(link.link.url, 'https://www.shodan.io/host/198.51.100.20');
});

test('configuration: nothing to watch, private addresses ignored and said', async (t) => {
  const env = await startApp(t, {
    config: { monitor_public_ip: false, addresses: '192.168.1.1, box', language: 'fr' },
  });
  await run(env, 2 * MINUTE);
  assert.deepEqual(env.fake.calls, []);
  assert.deepEqual(env.gladys.fake.discoveredDevices, []);
  assert.equal(env.gladys.fake.connectionStatus.connected, false);
  assert.equal(
    env.gladys.fake.connectionStatus.message.fr,
    'Rien à surveiller : activez l’adresse publique ou saisissez une adresse. Ignorées (privées ou invalides) : 192.168.1.1, box.',
  );
  const message = (await env.gladys.fake.action(ACTIONS.TEST_CONNECTION)).data.message;
  assert.match(message.en, /Nothing to watch/);
});

test('test the connection: the public address, the source, the plan', async (t) => {
  const env = await startApp(t, { config: { ...CONFIG, api_key: KEY } });
  const message = (await env.gladys.fake.action(ACTIONS.TEST_CONNECTION)).data.message;
  assert.equal(
    message.en,
    'Shodan answers. Public address: 203.0.113.7. 1 address(es) read with Shodan API. Plan: dev, 87 scan credit(s).',
  );
  env.fake.down.add('api');
  env.fake.down.add('internetdb');
  const down = await startApp(t, { fake: env.fake, clock: env.clock });
  const failed = (await down.gladys.fake.action(ACTIONS.TEST_CONNECTION)).data.message;
  assert.match(failed.en, /cannot be reached/);
});

test('restart: what was read comes back from /data, no event at the first round', async (t) => {
  const dir = dataDir();
  const first = await startApp(t, { dir });
  await run(first, 2 * MINUTE);
  await first.gladys.fake.shutdown();
  const clock = { now: first.clock.now + HOUR };
  const second = await startApp(t, { dir, clock });
  await run(second, 2 * MINUTE);
  assert.equal(second.fake.callsTo(`/${HOME}`).length, 0, 'not due yet');
  assert.equal(second.app.viewOf(second.app.targets()[0], 'en').reading.ports.length, 2);
  assert.deepEqual(second.gladys.fake.sceneEvents, []);
});
