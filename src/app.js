// -----------------------------------------------------------------------------
// The Shodan integration: every handler, registered on a Gladys client.
//
// Shows in Gladys what the Internet sees of the home: the public address of
// the home and the addresses the user types (a dynamic DNS name, a server),
// as Shodan knows them, read only:
//   - devices (device.js): one per address (open ports, vulnerabilities,
//     address, exposed ports);
//   - scene triggers (events.js): port opened or closed, vulnerability found
//     or gone, Shodan tag added, public address changed, key refused;
//   - scene actions: values of an address (no request), look up any
//     address, ask Shodan for a scan (paid plan);
//   - dashboard widgets (widgets.js): overview, one address, account;
//   - configuration buttons: test the connection, diagnostic.
//
// Sources: without a key, Shodan InternetDB (free for non-commercial use,
// refreshed once a week); with a key, the Shodan API (services, versions,
// CVSS, date of the last scan, credits, on-demand scan), InternetDB taking
// over when the key is refused or its plan does not allow a host lookup.
//
// Pace: a timer checks every minute what is due: the public address every
// 15 minutes (it may change at any time), each address every 6 hours (the
// data of Shodan changes about once a week) or as soon as its IP changed, a
// retry 30 minutes after a failure, the credits every 6 hours, a scan asked
// every 2 minutes until it is done. The scene triggers are worked out after
// each round, never from a scene action.
//
// index.js only creates the SDK client; the tests drive this module with the
// fake Gladys of the SDK and a fake Shodan (test/helpers/fake-shodan.js).
// -----------------------------------------------------------------------------

import { readFileSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { logger as sdkLogger } from '@gladysassistant/integration-sdk';
import {
  normalizeConfig,
  readLanguage,
  guessLanguage,
  INTERNAL_KEYS,
  AUTO_LANGUAGE,
} from './config.js';
import { createShodanClient } from './shodan-api.js';
import { createStore } from './store.js';
import {
  notFound,
  parseInternetDb,
  parseHost,
  parseApiInfo,
  parseAddresses,
  isPublicIp,
} from './parse.js';
import {
  PUBLIC_ID,
  platformId,
  targetIds,
  targetOfExternalId,
  defaultName,
  buildTargetDevice,
  buildTargetStates,
} from './device.js';
import {
  TRIGGERS,
  SCENE_ACTIONS,
  TARGET_OUTPUTS,
  LOOKUP_OUTPUTS,
  SCAN_OUTPUTS,
  pick,
  detectTarget,
  targetEventData,
  readingOutputs,
  summaryText,
} from './events.js';
import {
  WIDGETS,
  WIDGET_ACTIONS,
  messageContent,
  buildOverviewWidget,
  buildTargetWidget,
  buildAccountWidget,
} from './widgets.js';
import { MINUTE_MS, HOUR_MS, defaultTimeZone, usableTimeZone } from './time.js';
import { t, tn, all, LANGUAGES } from './i18n.js';

const ACTIONS = {
  TEST_CONNECTION: 'test_connection',
  DIAGNOSTIC: 'diagnostic',
};
const TICK_MS = MINUTE_MS;
const STARTUP_DELAY_MS = 5 * 1000;
const PUBLIC_IP_EVERY_MS = 15 * MINUTE_MS;
const READ_EVERY_MS = 6 * HOUR_MS;
const RETRY_MS = 30 * MINUTE_MS;
const KEY_RETRY_MS = 6 * HOUR_MS;
const API_INFO_EVERY_MS = 6 * HOUR_MS;
const HOST_DENIED_MS = 24 * HOUR_MS;
const SCAN_CHECK_MS = 2 * MINUTE_MS;
const SCAN_GIVE_UP_MS = 2 * HOUR_MS;
const BUTTON_MIN_MS = MINUTE_MS;
// Re-send unchanged values, so that Gladys does not show them as outdated.
const HEARTBEAT_MS = 12 * HOUR_MS;
const DIAGNOSTIC_CHUNK = 3000;
const { version: VERSION } = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
);
const USER_AGENT = `gladys-shodan/${VERSION} (+https://github.com/William-De71/gladys-shodan)`;

/**
 * @description The public addresses a host name resolves to, IPv4 first.
 * @param {string} host - The host name.
 * @returns {Promise<string[]>} The addresses.
 */
async function resolveHost(host) {
  const answers = await lookup(host, { all: true, verbatim: false });
  return answers.map((answer) => answer.address);
}

/**
 * @description Register every handler of the integration on a Gladys client.
 * @param {object} gladys - A GladysIntegration (or the fake Gladys of the SDK).
 * @param {object} [options] - Options.
 * @param {Function} [options.fetch] - HTTP transport of Shodan (tests).
 * @param {string} [options.apiUrl] - The API root (tests).
 * @param {string} [options.internetDbUrl] - The InternetDB root (tests).
 * @param {Function} [options.resolve] - `(host) => Promise<string[]>` (tests).
 * @param {string} [options.dataDir] - The writable folder (/data).
 * @param {Function} [options.now] - `() => number` in ms (tests).
 * @param {Function} [options.sleep] - `(ms) => Promise` (tests).
 * @param {string} [options.timeZone] - IANA timezone of Gladys (TZ by default).
 * @param {boolean} [options.timers] - Arm the timer (false in tests).
 * @param {object} [options.logger] - Logger.
 * @returns {object} Handles for the tests.
 */
function createApp(
  gladys,
  {
    fetch: fetchFn,
    apiUrl,
    internetDbUrl,
    resolve = resolveHost,
    dataDir,
    now = () => Date.now(),
    sleep,
    timeZone: zone = defaultTimeZone(),
    timers = true,
    logger = sdkLogger,
  } = {},
) {
  const timeZone = usableTimeZone(zone);
  let config = normalizeConfig();
  let language = guessLanguage(timeZone);
  let createdNames = new Map();
  let lastStatus = null;
  let lastDiscovery = null;
  let timer = null;
  let startTimer = null;
  let running = null;
  let stopped = false;
  // Why the last check of the public address failed (null: it answered).
  let publicIpError = null;

  const store = createStore({ ...(dataDir ? { dir: dataDir } : {}), logger });
  const api = createShodanClient({
    getKey: () => config.apiKey,
    userAgent: USER_AGENT,
    now,
    ...(sleep ? { sleep } : {}),
    ...(fetchFn ? { fetch: fetchFn } : {}),
    ...(apiUrl ? { apiUrl } : {}),
    ...(internetDbUrl ? { internetDbUrl } : {}),
  });

  /**
   * @description Remember the language of a widget request, and store it when it changed.
   * @param {string} next - The language.
   */
  function rememberLanguage(next) {
    if (!LANGUAGES.includes(next) || next === language) {
      return;
    }
    language = next;
    gladys
      .setConfig({ [INTERNAL_KEYS.language]: next })
      .catch((err) => logger.warn(`Unable to store the language: ${err.message}`));
  }

  /**
   * @description Language of the texts Gladys does not ask for in a language.
   * @returns {string} The language.
   */
  const textLanguage = () => (config.language === AUTO_LANGUAGE ? language : config.language);

  // --- Targets -----------------------------------------------------------------------

  /**
   * @description The addresses to watch, from the configuration.
   * @returns {object[]} `{ id, kind: 'public' | 'ip' | 'host', address }`.
   */
  function targets() {
    return [
      ...(config.monitorPublicIp ? [{ id: PUBLIC_ID, kind: 'public', address: null }] : []),
      ...config.addresses.map(({ address, kind }) => ({ id: address, kind, address })),
    ];
  }

  /**
   * @description What is kept of a target.
   * @param {object} target - The target.
   * @returns {object} `{ ip, reading, readAt, triedAt, error }`.
   */
  function stateOf(target) {
    if (!store.data.targets[target.id]) {
      store.data.targets[target.id] = {
        ip: null,
        reading: null,
        readAt: 0,
        triedAt: 0,
        error: null,
      };
    }
    return store.data.targets[target.id];
  }

  /**
   * @description The view of a target the widgets, the scenes and the states use.
   * @param {object} target - The target.
   * @param {string} lang - The language of the texts.
   * @returns {object} The view.
   */
  function viewOf(target, lang) {
    const state = stateOf(target);
    const deviceId = targetIds(gladys, target).device;
    return {
      target,
      deviceId,
      platformId: platformId(target),
      // The name the user gave in Gladys, else the default one.
      name: createdNames.get(deviceId) || defaultName(target, lang),
      ip: state.ip,
      reading: state.reading,
      readAt: state.readAt,
      error: state.error ? errorText(state.error, lang) : null,
    };
  }

  /**
   * @description The target a widget or a scene action points at.
   * @param {unknown} value - A device external id (`source: "devices"`) or a platform id.
   * @returns {object|null} The target, the first one by default.
   */
  function findTarget(value) {
    const list = targets();
    const id = targetOfExternalId(value) ?? (typeof value === 'string' ? value : null);
    return list.find((target) => platformId(target) === id) ?? list[0] ?? null;
  }

  // --- Errors and status -------------------------------------------------------------

  /**
   * @description The message of an error, for a user.
   * @param {object} err - The error (`kind`, `detail`, `host`, `address`).
   * @param {string} lang - The language.
   * @returns {string} The message.
   */
  function errorText(err, lang) {
    switch (err?.kind) {
      case 'auth':
        return t(err.code === 'missing' ? 'errNoKey' : 'errAuth', lang);
      case 'plan':
        return t('errPlan', lang, { detail: err.detail || 'HTTP 403' });
      case 'invalid':
        return t('errInvalid', lang);
      case 'dns':
        return t('errDns', lang, { host: err.host });
      case 'address':
        return t('errAddress', lang, { address: err.address });
      case 'no_public_ip':
        return t('errNoPublicIp', lang);
      case 'rate_limit':
        return t('errPaused', lang);
      case 'server':
        return t('errServer', lang);
      case 'unreachable':
        return t('errUnreachable', lang);
      default:
        return t('errFailed', lang, {
          detail: String(err?.detail || err?.message || '').slice(0, 120),
        });
    }
  }

  /**
   * @description What is kept of an error (never the key).
   * @param {object} err - The error.
   * @returns {object} `{ kind, code, detail, host, address }`.
   */
  const errorOf = (err) => ({
    kind: err.kind ?? 'failed',
    ...(err.code ? { code: err.code } : {}),
    detail: String(err.detail || err.message || '').slice(0, 200),
    ...(err.host ? { host: err.host } : {}),
    ...(err.address ? { address: err.address } : {}),
  });

  /**
   * @description Report the connection status, only when it changed.
   * @param {boolean} connected - Connected or not.
   * @param {object} message - The multi-language message.
   * @returns {Promise<void>}
   */
  async function reportStatus(connected, message) {
    const clipped = Object.fromEntries(
      Object.entries(message).map(([lang, text]) => [lang, text.slice(0, 200)]),
    );
    const signature = JSON.stringify([connected, clipped]);
    if (signature === lastStatus) {
      return;
    }
    lastStatus = signature;
    try {
      await gladys.setConnectionStatus(connected, clipped);
    } catch (err) {
      lastStatus = null;
      logger.error('Unable to report the connection status', err);
    }
  }

  /**
   * @description Work out the connection status.
   * @returns {Promise<void>}
   */
  async function refreshStatus() {
    const list = targets();
    const extras = (lang) => [
      ...(config.apiKey && store.data.accessRefused ? [t('statusKeyFallback', lang)] : []),
      ...(api.pausedUntil() ? [t('statusPaused', lang)] : []),
      ...(config.rejected.length
        ? [t('statusRejected', lang, { list: config.rejected.slice(0, 5).join(', ') })]
        : []),
    ];
    if (list.length === 0) {
      await reportStatus(
        false,
        all((lang) => [t('statusNoTarget', lang), ...extras(lang)].join(' ')),
      );
      return;
    }
    const states = list.map(stateOf);
    const read = states.filter((state) => state.reading);
    if (read.length === 0) {
      const failed = states.find((state) => state.error);
      await reportStatus(
        !failed,
        all((lang) =>
          [failed ? errorText(failed.error, lang) : t('statusWaiting', lang), ...extras(lang)].join(
            ' ',
          ),
        ),
      );
      return;
    }
    const ports = read.reduce((sum, state) => sum + state.reading.ports.length, 0);
    const vulns = read.reduce((sum, state) => sum + state.reading.vulns.length, 0);
    await reportStatus(
      true,
      all((lang) =>
        [tn('statusOk', list.length, lang, { ports, vulns }), ...extras(lang)].join(' '),
      ),
    );
  }

  /**
   * @description Refresh the devices the user created, and their names.
   * @returns {Promise<void>}
   */
  async function refreshCreatedDevices() {
    try {
      const devices = await gladys.getDevices();
      createdNames = new Map(devices.map((device) => [device.external_id, device.name ?? '']));
    } catch (err) {
      logger.warn(`Unable to read the devices: ${err.message}`);
    }
  }

  /**
   * @description Ask the open widgets to pull their content again.
   */
  function refreshWidgets() {
    for (const key of Object.values(WIDGETS)) {
      Promise.resolve(gladys.requestWidgetRefresh(key)).catch(() => {});
    }
  }

  /**
   * @description Publish scene events, one by one.
   * @param {Array<{ key: string, data: object }>} events - The events.
   * @returns {Promise<void>}
   */
  async function publishEvents(events) {
    for (const { key, data } of events) {
      logger.info(`Shodan: ${key}${data.ip ? ` (${data.ip})` : ''}`);
      try {
        await gladys.publishSceneEvent(key, data);
      } catch (err) {
        logger.warn(`Unable to fire ${key}: ${err.message}`);
      }
    }
  }

  // --- Devices -----------------------------------------------------------------------

  /**
   * @description Offer the devices of the targets, when they changed.
   * @param {boolean} [force] - Publish even when unchanged.
   * @returns {Promise<number>} How many devices were offered.
   */
  async function publishDiscoveredDevices(force = false) {
    const lang = textLanguage();
    const devices = targets().map((target) =>
      buildTargetDevice(gladys, target, { language: lang }),
    );
    const signature = JSON.stringify(devices);
    if (force || signature !== lastDiscovery) {
      await gladys.publishDiscoveredDevices(devices);
      lastDiscovery = signature;
    }
    return devices.length;
  }

  /**
   * @description Publish the states of every created device.
   * @returns {Promise<void>}
   */
  async function publishAllStates() {
    const lang = textLanguage();
    for (const target of targets()) {
      if (!createdNames.has(targetIds(gladys, target).device)) {
        continue;
      }
      const states = buildTargetStates(gladys, target, stateOf(target).reading, { language: lang });
      if (states.length === 0) {
        continue;
      }
      await gladys
        .publishChangedStates(states, { heartbeat: HEARTBEAT_MS })
        .catch((err) =>
          logger.warn(`Unable to publish the states of ${target.id}: ${err.message}`),
        );
    }
  }

  // --- Reading -----------------------------------------------------------------------

  /**
   * @description Note an error (diagnostic).
   * @param {Error} err - The error.
   * @param {string} [what] - What was read.
   */
  function noteError(err, what = '') {
    logger.warn(`Shodan${what ? ` ${what}` : ''} (${err.kind ?? 'failed'}): ${err.message}`);
    store.data.lastError = { ...errorOf(err), at: now() };
  }

  /**
   * @description Remember that Shodan refuses the key (the trigger fires once, from the timer).
   * @param {object} err - The error.
   */
  function keyRefused(err) {
    const code = 'refused';
    const announced = store.data.accessRefused?.code === code && store.data.accessRefused.announced;
    store.data.accessRefused = { kind: err.kind, code, at: now(), announced: Boolean(announced) };
  }

  /**
   * @description Whether the API is used for the host lookups now.
   * @returns {boolean} True with a key Shodan accepts, on a plan that allows it.
   */
  function useApi() {
    if (!api.hasKey()) return false;
    if (store.data.accessRefused && now() - store.data.accessRefused.at < KEY_RETRY_MS)
      return false;
    return now() >= store.data.hostDeniedUntil;
  }

  /**
   * @description Look an address up: the API with a key it accepts, else InternetDB.
   * @param {string} ip - The public address.
   * @param {object} [options] - `{ remember }` false for a one-off lookup (scene action).
   * @returns {Promise<object>} The reading.
   */
  async function lookupIp(ip, { remember = true } = {}) {
    if (useApi()) {
      try {
        const reading = parseHost(await api.host(ip), ip);
        if (remember && store.data.accessRefused) {
          logger.info('Shodan accepts the API key again');
          store.data.accessRefused = null;
        }
        return reading;
      } catch (err) {
        if (err.kind === 'not_found') {
          if (remember) store.data.accessRefused = null;
          return notFound(ip, 'api');
        }
        if (err.kind === 'auth') {
          if (remember) keyRefused(err);
        } else if (err.kind === 'plan') {
          // A plan without host lookups: InternetDB answers for a day.
          if (remember) store.data.hostDeniedUntil = now() + HOST_DENIED_MS;
        } else {
          throw err;
        }
        noteError(err, 'host lookup');
      }
    }
    try {
      return parseInternetDb(await api.internetDb(ip), ip);
    } catch (err) {
      if (err.kind === 'not_found') {
        return notFound(ip, 'internetdb');
      }
      throw err;
    }
  }

  /**
   * @description The public address to read for a host name.
   * @param {string} host - The host name.
   * @returns {Promise<string>} The address.
   */
  async function resolvePublic(host) {
    let addresses;
    try {
      addresses = await resolve(host);
    } catch {
      addresses = [];
    }
    const sorted = [...addresses].sort((a, b) => Number(b.includes('.')) - Number(a.includes('.')));
    const found = sorted.find(isPublicIp);
    if (!found) {
      throw Object.assign(new Error(`${host} has no public address`), { kind: 'dns', host });
    }
    return found;
  }

  /**
   * @description The address of a target now.
   * @param {object} target - The target.
   * @returns {Promise<string>} The address.
   */
  async function addressOf(target) {
    if (target.kind === 'public') {
      if (!store.data.publicIp) {
        throw (
          publicIpError ??
          Object.assign(new Error('Public address unknown'), { kind: 'no_public_ip' })
        );
      }
      return store.data.publicIp;
    }
    return target.kind === 'host' ? resolvePublic(target.address) : target.address;
  }

  /**
   * @description Check the public address of the home, when due.
   * @param {boolean} [force] - Check even when not due.
   * @returns {Promise<void>}
   */
  async function checkPublicIp(force = false) {
    if (!config.monitorPublicIp) return;
    if (
      !force &&
      store.data.publicIp &&
      now() - store.data.publicIpCheckedAt < PUBLIC_IP_EVERY_MS
    ) {
      return;
    }
    if (!force && api.pausedUntil('api')) return;
    try {
      const ip = await api.myIp();
      publicIpError = null;
      store.data.publicIpCheckedAt = now();
      if (ip !== store.data.publicIp) {
        logger.info(`Public address: ${ip}`);
        store.data.publicIp = ip;
      }
    } catch (err) {
      store.data.publicIpCheckedAt = now();
      publicIpError = err;
      noteError(err, 'public address');
    }
  }

  /**
   * @description Whether a target is due for a reading.
   * @param {object} state - stateOf(target).
   * @param {string|null} ip - Its address now (public target), null when unknown.
   * @returns {boolean} True when due.
   */
  function isDue(state, ip) {
    if (state.error && now() - state.triedAt < RETRY_MS) return false;
    if (!state.readAt || now() - state.readAt >= READ_EVERY_MS) return true;
    return Boolean(ip && state.ip && ip !== state.ip);
  }

  /**
   * @description Read a target.
   * @param {object} target - The target.
   * @returns {Promise<object|null>} The error, null when read.
   */
  async function readTarget(target) {
    const state = stateOf(target);
    state.triedAt = now();
    try {
      const ip = await addressOf(target);
      const reading = await lookupIp(ip);
      Object.assign(state, { ip, reading, readAt: now(), error: null });
      return null;
    } catch (err) {
      noteError(err, target.id);
      state.error = errorOf(err);
      return err;
    }
  }

  /**
   * @description Read every target due (or all of them).
   * @param {object} [options] - `{ force }`.
   * @returns {Promise<number>} How many targets were read.
   */
  async function readTargets({ force = false } = {}) {
    let count = 0;
    for (const target of targets()) {
      const state = stateOf(target);
      const ip = target.kind === 'public' ? store.data.publicIp : null;
      if (!force && (!isDue(state, ip) || (api.pausedUntil('internetdb') && !useApi()))) {
        continue;
      }
      if (!(await readTarget(target))) count += 1;
    }
    return count;
  }

  /**
   * @description Read the plan and the credits of the key, when due.
   * @param {boolean} [force] - Read even when not due.
   * @returns {Promise<void>}
   */
  async function readApiInfo(force = false) {
    if (!api.hasKey() || (!force && !useApi() && store.data.accessRefused)) return;
    if (!force && now() - store.data.apiInfoAt < API_INFO_EVERY_MS) return;
    try {
      store.data.apiInfo = parseApiInfo(await api.apiInfo());
      store.data.apiInfoAt = now();
      if (store.data.accessRefused) {
        store.data.accessRefused = null;
      }
    } catch (err) {
      store.data.apiInfoAt = now();
      noteError(err, 'api-info');
      if (err.kind === 'auth') keyRefused(err);
    }
  }

  /**
   * @description Follow the scans asked, until done.
   * @returns {Promise<void>}
   */
  async function followScans() {
    for (const scan of store.data.scans) {
      if (['DONE', 'FAILED'].includes(scan.status) || now() - scan.checkedAt < SCAN_CHECK_MS) {
        continue;
      }
      scan.checkedAt = now();
      try {
        const status = String((await api.scanStatus(scan.id))?.status ?? '').toUpperCase();
        if (['SUBMITTING', 'QUEUE', 'PROCESSING', 'DONE'].includes(status)) {
          scan.status = status;
        }
      } catch (err) {
        noteError(err, `scan ${scan.id}`);
      }
      if (scan.status === 'DONE') {
        // The new results: read the address again at once.
        const target = targets().find((item) => stateOf(item).ip === scan.ip);
        if (target) {
          stateOf(target).readAt = 0;
          stateOf(target).error = null;
        }
      } else if (now() - scan.at > SCAN_GIVE_UP_MS) {
        scan.status = 'FAILED';
      }
    }
  }

  /**
   * @description Work out the scene events from what was read (timer only).
   * @returns {Promise<void>}
   */
  async function detectEvents() {
    const events = [];
    const lang = textLanguage();
    const refusal = store.data.accessRefused;
    if (refusal && config.apiKey && !refusal.announced) {
      events.push({
        key: TRIGGERS.ACCESS_REFUSED,
        data: {
          reason: refusal.code,
          message: errorText({ kind: refusal.kind, detail: '' }, lang).slice(0, 1000),
        },
      });
      refusal.announced = true;
    }
    const publicIp = store.data.publicIp;
    if (publicIp && store.data.seen[PUBLIC_ID]?.announcedIp !== undefined) {
      const previous = store.data.seen[PUBLIC_ID].announcedIp;
      if (previous && previous !== publicIp) {
        events.push({
          key: TRIGGERS.PUBLIC_IP_CHANGED,
          data: { previous_ip: previous, ip: publicIp },
        });
      }
    }
    if (publicIp && config.monitorPublicIp) {
      store.data.seen[PUBLIC_ID] = { ...store.data.seen[PUBLIC_ID], announcedIp: publicIp };
    }
    const ids = new Set(targets().map((target) => target.id));
    for (const id of Object.keys(store.data.seen)) {
      if (!ids.has(id)) delete store.data.seen[id];
    }
    for (const id of Object.keys(store.data.targets)) {
      if (!ids.has(id)) delete store.data.targets[id];
    }
    for (const target of targets()) {
      const state = stateOf(target);
      if (!state.reading) continue;
      const remembered = store.data.seen[target.id] ?? {};
      if (remembered.readAt === state.readAt) continue;
      const found = detectTarget(remembered.memory, state.reading);
      store.data.seen[target.id] = { ...remembered, memory: found.next, readAt: state.readAt };
      const view = viewOf(target, lang);
      for (const event of found.events) {
        events.push({ key: event.key, data: targetEventData(view, event) });
      }
    }
    await store.save();
    if (events.length) {
      await publishEvents(events);
      refreshWidgets();
    }
  }

  /**
   * @description Publish what is known after readings.
   * @returns {Promise<void>}
   */
  async function publishAll() {
    await store.save();
    await publishDiscoveredDevices().catch((err) =>
      logger.warn(`Unable to offer the devices: ${err.message}`),
    );
    await publishAllStates();
    refreshWidgets();
  }

  /**
   * @description One round of the timer: what is due, then the triggers.
   * @returns {Promise<void>}
   */
  function tick() {
    if (!running) {
      running = (async () => {
        await checkPublicIp();
        await followScans();
        const read = await readTargets();
        await readApiInfo();
        await detectEvents();
        if (read) {
          await publishAll();
        }
        await refreshStatus();
      })()
        .catch((err) => logger.error('Readings', err))
        .finally(() => {
          running = null;
        });
    }
    return running;
  }

  /**
   * @description (Re)arm the timer.
   */
  function schedule() {
    clearInterval(timer);
    clearTimeout(startTimer);
    if (!timers || stopped) {
      return;
    }
    startTimer = setTimeout(tick, STARTUP_DELAY_MS);
    startTimer.unref?.();
    timer = setInterval(tick, TICK_MS);
    timer.unref?.();
  }

  /**
   * @description Offer the devices, publish what is known, arm the timer.
   * @returns {Promise<void>}
   */
  async function applyConfig() {
    await publishAll();
    await refreshStatus();
    schedule();
  }

  // --- Dashboard widgets -------------------------------------------------------------

  gladys.onWidgetGet(WIDGETS.OVERVIEW, async ({ language: lang } = {}) => {
    rememberLanguage(lang);
    const list = targets();
    if (list.length === 0) {
      return messageContent(t('statusNoTarget', lang));
    }
    return buildOverviewWidget({
      views: list.map((target) => viewOf(target, lang)),
      language: lang,
      now: now(),
      hasKey: useApi(),
    });
  });

  gladys.onWidgetGet(WIDGETS.TARGET, async ({ settings = {}, language: lang } = {}) => {
    rememberLanguage(lang);
    const target = findTarget(settings.target);
    if (!target) {
      return messageContent(t('statusNoTarget', lang));
    }
    return buildTargetWidget({ view: viewOf(target, lang), language: lang, now: now(), timeZone });
  });

  gladys.onWidgetAction(WIDGETS.TARGET, async (actionKey, params = {}) => {
    if (actionKey !== WIDGET_ACTIONS.REFRESH) {
      return undefined;
    }
    const target = findTarget(params.target);
    if (!target) {
      return all('errNoTarget');
    }
    const state = stateOf(target);
    if (now() - state.triedAt < BUTTON_MIN_MS) {
      return all('toastTooSoon');
    }
    if (target.kind === 'public') {
      await checkPublicIp(true);
    }
    const error = await readTarget(target);
    await publishAll();
    await refreshStatus();
    if (error) {
      return all((lang) => errorText(errorOf(error), lang).slice(0, 200));
    }
    return all('toastRefreshed', {
      count: state.reading.ports.length,
      vulns: state.reading.vulns.length,
    });
  });

  gladys.onWidgetGet(WIDGETS.ACCOUNT, async ({ language: lang } = {}) => {
    rememberLanguage(lang);
    if (!config.apiKey) {
      return messageContent(t('errNoKey', lang));
    }
    if (!store.data.apiInfo) {
      return messageContent(
        store.data.accessRefused ? t('errAuth', lang) : t('statusWaiting', lang),
      );
    }
    return buildAccountWidget({
      info: store.data.apiInfo,
      readAt: store.data.apiInfoAt,
      scans: store.data.scans,
      language: lang,
      now: now(),
    });
  });

  // --- Scene actions -----------------------------------------------------------------

  // Answers from what the timer read: no request.
  gladys.onSceneAction(SCENE_ACTIONS.GET_TARGET, async (fields = {}) => {
    const lang = textLanguage();
    const target = findTarget(fields.target);
    const view = target ? viewOf(target, lang) : null;
    if (!view?.reading) {
      throw new Error(view?.error ?? t('errNoTarget', lang));
    }
    const iso = (instant) =>
      Number.isFinite(instant) && instant ? new Date(instant).toISOString() : null;
    return pick(
      {
        ...readingOutputs(view.reading, lang),
        target_name: view.name,
        last_scan: iso(view.reading.lastUpdate),
        read_at: iso(view.readAt),
        summary: summaryText(view.reading, lang, view.name),
      },
      TARGET_OUTPUTS,
    );
  });

  // Any public address or host name, read now (one request).
  gladys.onSceneAction(SCENE_ACTIONS.LOOKUP_ADDRESS, async (fields = {}) => {
    const lang = textLanguage();
    const raw = String(fields.address ?? '').trim();
    const { addresses } = parseAddresses(raw);
    const entry = addresses[0];
    if (!entry || addresses.length > 1) {
      throw new Error(t('errAddress', lang, { address: raw.slice(0, 64) }));
    }
    try {
      const ip = entry.kind === 'host' ? await resolvePublic(entry.address) : entry.address;
      const reading = await lookupIp(ip, { remember: false });
      return pick({ ...readingOutputs(reading, lang), found: reading.found }, LOOKUP_OUTPUTS);
    } catch (err) {
      throw new Error(errorText(errorOf(err), lang), { cause: err });
    }
  });

  // A paid plan: 1 scan credit; the address is read again once the scan is done.
  gladys.onSceneAction(SCENE_ACTIONS.REQUEST_SCAN, async (fields = {}) => {
    const lang = textLanguage();
    if (!config.apiKey) {
      throw new Error(t('errNoKey', lang));
    }
    const target = findTarget(fields.target);
    const ip = target ? stateOf(target).ip : null;
    if (!ip) {
      throw new Error(t('errNoTarget', lang));
    }
    try {
      const answer = await api.scan(ip);
      const id = String(answer?.id ?? '').slice(0, 64);
      if (!id) {
        throw Object.assign(new Error('Unexpected answer of /shodan/scan'), { kind: 'failed' });
      }
      store.data.scans = [
        ...store.data.scans,
        { id, ip, status: 'SUBMITTING', at: now(), checkedAt: now() },
      ].slice(-10);
      const credits = Number(answer.credits_left);
      if (store.data.apiInfo && Number.isFinite(credits)) {
        store.data.apiInfo.scanCredits = credits;
      }
      await store.save();
      refreshWidgets();
      return pick(
        { scan_id: id, ip, credits_left: Number.isFinite(credits) ? credits : null },
        SCAN_OUTPUTS,
      );
    } catch (err) {
      noteError(err, 'scan');
      throw new Error(errorText(errorOf(err), lang), { cause: err });
    }
  });

  // --- Configuration screen actions --------------------------------------------------

  gladys.onAction(ACTIONS.TEST_CONNECTION, async () => {
    const list = targets();
    if (list.length === 0) {
      return all('statusNoTarget');
    }
    store.data.accessRefused = null;
    store.data.hostDeniedUntil = 0;
    await checkPublicIp(true);
    const errors = [];
    for (const target of list) {
      const error = await readTarget(target);
      if (error) errors.push(error);
    }
    await readApiInfo(true);
    await publishAll();
    lastStatus = null;
    await refreshStatus();
    schedule();
    if (errors.length === list.length) {
      return all((lang) => errorText(errorOf(errors[0]), lang));
    }
    const info = store.data.apiInfo;
    return all((lang) =>
      t('testOk', lang, {
        ip: store.data.publicIp ?? '–',
        count: list.length - errors.length,
        source: t(useApi() ? 'sourceApi' : 'sourceInternetDb', lang),
        plan:
          config.apiKey && info && !store.data.accessRefused
            ? t('testPlan', lang, { plan: info.plan ?? '–', credits: info.scanCredits ?? 0 })
            : config.apiKey && store.data.accessRefused
              ? ` ${t('statusKeyFallback', lang)}`
              : '',
      }).slice(0, 1000),
    );
  });

  gladys.onAction(ACTIONS.DIAGNOSTIC, async () => {
    const iso = (value) => (Number.isFinite(value) && value ? new Date(value).toISOString() : null);
    const data = store.data;
    const report = {
      version: VERSION,
      timeZone,
      apiKey: config.apiKey ? 'set' : 'missing',
      monitorPublicIp: config.monitorPublicIp,
      addresses: config.addresses,
      rejected: config.rejected,
      language: config.language,
      useApi: useApi(),
      publicIp: data.publicIp,
      publicIpCheckedAt: iso(data.publicIpCheckedAt),
      accessRefused: data.accessRefused,
      hostDeniedUntil: iso(data.hostDeniedUntil),
      lastError: data.lastError,
      apiInfo: data.apiInfo,
      scans: data.scans,
      api: {
        ...api.counts(),
        pausedApi: iso(api.pausedUntil('api')),
        pausedInternetDb: iso(api.pausedUntil('internetdb')),
      },
      targets: targets().map((target) => {
        const state = stateOf(target);
        return {
          ...target,
          created: createdNames.has(targetIds(gladys, target).device),
          ip: state.ip,
          readAt: iso(state.readAt),
          triedAt: iso(state.triedAt),
          error: state.error,
          reading: state.reading
            ? {
                source: state.reading.source,
                found: state.reading.found,
                ports: state.reading.ports,
                vulns: state.reading.vulns.length,
                tags: state.reading.tags,
              }
            : null,
        };
      }),
    };
    const json = JSON.stringify(report);
    const count = Math.max(1, Math.ceil(json.length / DIAGNOSTIC_CHUNK));
    for (let chunk = 0; chunk < count; chunk += 1) {
      logger.info(
        `Shodan diagnostic ${chunk + 1}/${count}: ${json.slice(chunk * DIAGNOSTIC_CHUNK, (chunk + 1) * DIAGNOSTIC_CHUNK)}`,
      );
    }
    return all('diagnosticDone', { count });
  });

  // --- Devices -----------------------------------------------------------------------
  gladys.onScanRequest(async () => {
    const count = await publishDiscoveredDevices(true);
    logger.info(`Scan: ${count} device(s) offered`);
  });

  gladys.onDeviceCreated(async () => {
    await refreshCreatedDevices();
    // States sent before the device existed were dropped by Gladys, and the SDK
    // forgot what it sent for this device: send everything known again.
    await publishAllStates();
    refreshWidgets();
  });

  gladys.onDeviceUpdated(refreshCreatedDevices);
  gladys.onDeviceDeleted(refreshCreatedDevices);

  // --- Configuration -----------------------------------------------------------------

  /**
   * @description Reload the whole config (internal keys included).
   * @param {object} [fallback] - Raw values to use when the read fails.
   * @returns {Promise<void>}
   */
  async function loadConfig(fallback) {
    try {
      const raw = await gladys.getConfig();
      config = normalizeConfig(raw);
      language = readLanguage(raw, language);
    } catch (err) {
      if (fallback) {
        config = normalizeConfig(fallback);
      }
      logger.error('Unable to read the configuration', err);
    }
  }

  gladys.onConfigUpdated(async (rawConfig) => {
    const previous = config;
    await loadConfig(rawConfig);
    logger.info('Configuration updated');
    lastStatus = null;
    lastDiscovery = null;
    if (previous.apiKey !== config.apiKey) {
      // Another key (or none): a new source, the credits to read again.
      store.data.accessRefused = null;
      store.data.hostDeniedUntil = 0;
      store.data.apiInfo = null;
      store.data.apiInfoAt = 0;
      for (const state of Object.values(store.data.targets)) {
        state.readAt = 0;
        state.error = null;
      }
    }
    await applyConfig();
    if (timers) {
      tick();
    }
  });

  // --- Connection lifecycle ----------------------------------------------------------
  // Each (re)connection resynchronizes; the promise lets the tests wait for it.
  let startup = Promise.resolve();
  gladys.on('connected', () => {
    startup = (async () => {
      await store.load();
      await loadConfig();
      await refreshCreatedDevices();
      lastStatus = null;
      lastDiscovery = null;
      await applyConfig();
    })().catch((err) => logger.error('Startup', err));
  });

  // --- Graceful shutdown -------------------------------------------------------------
  gladys.handleShutdown(async (signal) => {
    logger.info(`Received ${signal} -> graceful shutdown`);
    stopped = true;
    clearInterval(timer);
    clearTimeout(startTimer);
    await store.save();
  });

  return {
    store,
    api,
    tick,
    targets,
    readTargets,
    detectEvents,
    viewOf,
    useApi,
    getConfig: () => config,
    whenReady: () => startup,
  };
}

export {
  createApp,
  ACTIONS,
  USER_AGENT,
  PUBLIC_IP_EVERY_MS,
  READ_EVERY_MS,
  RETRY_MS,
  KEY_RETRY_MS,
  HOST_DENIED_MS,
  SCAN_CHECK_MS,
  HEARTBEAT_MS,
};
