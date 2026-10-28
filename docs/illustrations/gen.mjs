// Widget contents for the generated illustrations, built by the real code of
// the integration: the app itself (src/app.js) wired to the fake Gladys of the
// SDK and the fake Shodan of the tests (test/helpers/fake-shodan.js, the
// answers of test/fixtures/hosts.json), with an API key, on Wednesday,
// 28 October 2026 at 10:00 in Paris: the public address of a home (SSH and a
// web server with two CVE) and a NAS reached by a dynamic DNS name. Made-up
// documentation addresses (RFC 5737): never real data.
// Written as JSON for render.js: node gen.mjs <repo> <out.json>

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [repo, out] = process.argv.slice(2);
const load = (file) => import(pathToFileURL(join(repo, file)).href);
const { createApp } = await load('src/app.js');
const { LANGUAGES } = await load('src/i18n.js');
const { createFakeGladys } = await import(
  pathToFileURL(join(repo, 'node_modules/@gladysassistant/integration-sdk/lib/testing.js')).href
);
const { createFakeShodan, dataDir, recordingLogger, KEY } = await load(
  'test/helpers/fake-shodan.js',
);

const NOW = Date.parse('2026-10-28T09:00:00Z');
const MINUTE = 60 * 1000;
const manifest = JSON.parse(readFileSync(join(repo, 'gladys-assistant-integration.json'), 'utf8'));
const WIDGET_KEYS = ['overview', 'target', 'account'];
const NAS = 'nas.example.org';
const NAS_IP = '198.51.100.20';
// The names a user would give the devices in Gladys.
const NAMES = {
  en: { public: 'Home box', 'nas-example-org': 'NAS' },
  fr: { public: 'Box de la maison', 'nas-example-org': 'NAS' },
  de: { public: 'Router zu Hause', 'nas-example-org': 'NAS' },
  es: { public: 'Router de casa', 'nas-example-org': 'NAS' },
};

/**
 * @description One language: the app read once, then the three widgets.
 * @param {string} language - Language.
 * @returns {Promise<object>} The widget contents.
 */
async function contents(language) {
  const clock = { now: NOW - 5 * MINUTE };
  const fake = createFakeShodan({ clock });
  fake.hosts[NAS_IP] = {
    ip_str: NAS_IP,
    ports: [5001],
    hostnames: [NAS],
    org: 'Example Telecom',
    isp: 'Example Telecom',
    tags: ['self-signed'],
    last_update: '2026-10-24T17:40:02.118000',
    data: [{ port: 5001, transport: 'tcp', product: 'nginx', timestamp: '2026-10-24T17:40:02' }],
  };
  const gladys = createFakeGladys({
    config: { monitor_public_ip: true, addresses: NAS, api_key: KEY, language },
  });
  const app = createApp(gladys, {
    fetch: (url, init) => fake.fetch(url, init),
    apiUrl: fake.apiUrl,
    internetDbUrl: fake.internetDbUrl,
    resolve: async () => [NAS_IP],
    dataDir: dataDir(),
    now: () => clock.now,
    sleep: async (ms) => {
      clock.now += ms;
    },
    timeZone: 'Europe/Paris',
    timers: false,
    logger: recordingLogger(),
  });
  await gladys.connect();
  await app.whenReady();
  await app.tick();
  for (const device of gladys.fake.discoveredDevices) {
    const id = device.external_id.split(':').pop();
    await gladys.fake.deviceCreated({ ...structuredClone(device), name: NAMES[language][id] });
  }
  // A scan asked a few minutes earlier, still running.
  await gladys.fake.sceneAction('request_scan', {});
  fake.scans.get('SCAN1').status = 'PROCESSING';
  clock.now += 3 * MINUTE;
  await app.tick();
  clock.now = NOW;
  const settings = { target: 'ext:test-integration:target:public' };
  const result = {};
  for (const key of WIDGET_KEYS) {
    result[key] = (await gladys.fake.widgetGet(key, { settings, language })).data.content;
  }
  await gladys.fake.shutdown();
  return result;
}

const all = {};
for (const language of LANGUAGES) {
  all[language] = await contents(language);
}

const card = (key) => {
  const widget = manifest.widgets.find((item) => item.key === key);
  return { icon: widget.icon, label: widget.label };
};
writeFileSync(
  out,
  JSON.stringify({
    contents: all,
    images: {},
    cards: Object.fromEntries(WIDGET_KEYS.map((key) => [key, card(key)])),
    now: NOW,
  }),
);
