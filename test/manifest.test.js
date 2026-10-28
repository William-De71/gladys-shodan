import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  TRIGGERS,
  SCENE_ACTIONS,
  TARGET_OUTPUTS,
  LOOKUP_OUTPUTS,
  SCAN_OUTPUTS,
  TAGS,
} from '../src/events.js';
import { ACTIONS } from '../src/app.js';
import { WIDGETS } from '../src/widgets.js';
import { AUTO_LANGUAGE, normalizeConfig } from '../src/config.js';
import { LANGUAGES } from '../src/i18n.js';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const manifest = read('../gladys-assistant-integration.json');
const pkg = read('../package.json');
const byKey = (list) => new Map(list.map((entry) => [entry.key, entry]));
const values = (field) => field.options.map((option) => option.value);
const source = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const REPO = 'William-De71/gladys-shodan';

test('a device integration, in lockstep with package.json, at 0.x until 1.0.0 is decided', () => {
  assert.equal(manifest.type, 'device');
  assert.equal(manifest.name, 'Shodan');
  assert.equal(manifest.version, pkg.version);
  assert.match(pkg.version, /^0\./);
  assert.equal(manifest.docker_image, `ghcr.io/william-de71/gladys-shodan:${pkg.version}`);
  assert.equal(manifest.cover_image, `https://raw.githubusercontent.com/${REPO}/main/cover.jpg`);
  assert.equal(pkg.license, 'Apache-2.0');
  assert.equal(pkg.name, 'gladys-shodan');
});

test('declares the cloud transport: the two Shodan services only, every request through the client', () => {
  assert.deepEqual(manifest.transports, ['cloud']);
  const api = source('../src/shodan-api.js');
  assert.match(api, /'https:\/\/api\.shodan\.io'/);
  assert.match(api, /'https:\/\/internetdb\.shodan\.io'/);
  for (const path of ['/tools/myip', '/api-info', '/shodan/scan', '/shodan/host/']) {
    assert.ok(api.includes(path), path);
  }
  for (const file of ['app', 'parse', 'events', 'widgets', 'device', 'store', 'time', 'config']) {
    assert.doesNotMatch(source(`../src/${file}.js`), /fetch\(|node:https?|node:dgram/, file);
  }
  // A single channel: no transport to publish per device.
  assert.doesNotMatch(source('../src/app.js'), /publishTransports|GLADYS_PREFER_LOCAL/);
});

test('Gladys 5.3.0 for the catalog keywords, worldwide, no permission', () => {
  assert.equal(manifest.gladys_version, '>=5.3.0');
  assert.deepEqual(manifest.categories, ['security', 'servers']);
  assert.equal(manifest.countries, undefined, 'worldwide');
  assert.ok(manifest.keywords.length >= 1 && manifest.keywords.length <= 10);
  const lower = manifest.keywords.map((word) => word.toLowerCase());
  assert.equal(new Set(lower).size, lower.length, 'unique keywords');
  for (const word of manifest.keywords) {
    assert.ok(word.length >= 2 && word.length <= 30, word);
  }
  for (const key of [
    'location',
    'network_wake',
    'containers',
    'network_discovery',
    'webhooks',
    'messaging',
    'energy_contracts',
    'music',
  ]) {
    assert.equal(manifest[key], undefined, key);
  }
});

test('config_schema: the fields the code reads, with their defaults', () => {
  const config = byKey(manifest.config_schema);
  assert.equal(config.get('monitor_public_ip').type, 'boolean');
  assert.equal(config.get('monitor_public_ip').default, true);
  assert.equal(config.get('addresses').type, 'string');
  assert.equal(config.get('api_key').type, 'secret');
  assert.equal(config.get('api_key').required, false, 'InternetDB works without a key');
  assert.deepEqual(values(config.get('language')), [AUTO_LANGUAGE, ...LANGUAGES]);
  assert.equal(config.get('language').default, AUTO_LANGUAGE);
  for (const field of manifest.config_schema) {
    assert.ok(!['text', 'password'].includes(field.type), `${field.key}: string / secret only`);
  }
  assert.deepEqual(normalizeConfig(), {
    monitorPublicIp: true,
    addresses: [],
    rejected: [],
    apiKey: '',
    language: AUTO_LANGUAGE,
  });
  assert.equal(normalizeConfig({ monitor_public_ip: false }).monitorPublicIp, false);
  assert.equal(normalizeConfig({ monitor_public_ip: 'false' }).monitorPublicIp, false);
  assert.equal(normalizeConfig({ api_key: ' abc DEF\n' }).apiKey, 'abcDEF');
  assert.equal(normalizeConfig({ language: 'it' }).language, AUTO_LANGUAGE);
});

test('configuration actions, widgets, triggers and the scene action match the code', () => {
  assert.deepEqual(
    manifest.actions.map((action) => action.key),
    Object.values(ACTIONS),
  );
  assert.deepEqual(
    manifest.widgets.map((widget) => widget.key),
    Object.values(WIDGETS),
  );
  assert.deepEqual(
    manifest.scene_triggers.map((trigger) => trigger.key),
    Object.values(TRIGGERS),
  );
  assert.deepEqual(
    manifest.scene_actions.map((action) => action.key),
    Object.values(SCENE_ACTIONS),
  );
  const actions = byKey(manifest.scene_actions);
  const outputs = (key) => actions.get(key).outputs.map((o) => o.key);
  assert.deepEqual(outputs('get_target'), TARGET_OUTPUTS);
  assert.deepEqual(outputs('lookup_address'), LOOKUP_OUTPUTS);
  assert.deepEqual(outputs('request_scan'), SCAN_OUTPUTS);
  for (const action of manifest.scene_actions) {
    assert.ok(action.timeout_seconds >= 5 && action.timeout_seconds <= 120, action.key);
  }
  const triggers = byKey(manifest.scene_triggers);
  const tag = byKey(triggers.get('tag_added').fields);
  assert.deepEqual(values(tag.get('tag')), TAGS);
  for (const trigger of manifest.scene_triggers) {
    assert.ok((trigger.fields ?? []).length <= 10, trigger.key);
    assert.ok(trigger.variables.length <= 20, trigger.key);
    for (const field of trigger.fields ?? []) {
      // A field filters by equality on the key of the same name of the data.
      assert.ok(
        trigger.variables.some((variable) => variable.key === field.key),
        `${trigger.key}.${field.key}`,
      );
    }
  }
  assert.ok(manifest.scene_triggers.length <= 20);
  assert.ok(manifest.widgets.length >= 1 && manifest.widgets.length <= 5);
  for (const widget of manifest.widgets) {
    for (const setting of widget.settings ?? []) {
      assert.ok(!['secret', 'oauth2', 'account_link'].includes(setting.type), setting.key);
    }
  }
});
