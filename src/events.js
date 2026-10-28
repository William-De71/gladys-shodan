// -----------------------------------------------------------------------------
// Scene triggers, the keys of the scene actions, and the comparison of two
// readings of a target.
//
// Triggers, once per transition, never at the first reading of a target,
// never because of a scene action (the detection runs on the timer only):
//   - `port_opened`          Shodan sees a port it did not see before;
//   - `port_closed`          a port Shodan saw is gone;
//   - `vulnerability_found`  a new CVE matched to the software Shodan saw;
//   - `vulnerability_gone`   a CVE is no longer matched (updated software);
//   - `tag_added`            Shodan tags the address (compromised, malware,
//                            self-signed, eol-product…);
//   - `public_ip_changed`    the public address of the home changed;
//   - `access_refused`       Shodan refuses the API key.
// A new address (the public one changed, a host name moved) starts a new
// baseline without any port or CVE event: what Shodan knows of a freshly
// assigned address may describe its previous holder. A change of source
// (InternetDB <-> API, a key added or removed) starts a new baseline too.
// A value to compare (>, <) is a feature of the device, not a trigger: "more
// than 0 vulnerabilities" is a device condition of the scene.
// -----------------------------------------------------------------------------

import { t, tn } from './i18n.js';
import { maxCvss, portsText } from './parse.js';

const TRIGGERS = {
  PORT_OPENED: 'port_opened',
  PORT_CLOSED: 'port_closed',
  VULNERABILITY_FOUND: 'vulnerability_found',
  VULNERABILITY_GONE: 'vulnerability_gone',
  TAG_ADDED: 'tag_added',
  PUBLIC_IP_CHANGED: 'public_ip_changed',
  ACCESS_REFUSED: 'access_refused',
};

const SCENE_ACTIONS = {
  GET_TARGET: 'get_target',
  LOOKUP_ADDRESS: 'lookup_address',
  REQUEST_SCAN: 'request_scan',
};

const TARGET_OUTPUTS = [
  'target_name',
  'ip',
  'port_count',
  'ports',
  'vuln_count',
  'vulns',
  'max_cvss',
  'tags',
  'hostnames',
  'source',
  'last_scan',
  'read_at',
  'summary',
];
const LOOKUP_OUTPUTS = [
  'ip',
  'found',
  'port_count',
  'ports',
  'vuln_count',
  'vulns',
  'max_cvss',
  'tags',
  'hostnames',
  'source',
  'summary',
];
const SCAN_OUTPUTS = ['scan_id', 'ip', 'credits_left'];

// The tags of Shodan (https://www.shodan.io/search/facet?query=&facet=tag),
// offered as filters of `tag_added`; another tag still fires the trigger.
const TAGS = [
  'compromised',
  'malware',
  'honeypot',
  'doublepulsar',
  'eol-product',
  'eol-os',
  'self-signed',
  'starttls',
  'database',
  'devops',
  'iot',
  'ics',
  'medical',
  'videogame',
  'vpn',
  'proxy',
  'tor',
  'cdn',
  'cloud',
  'scanner',
];
const ACCESS_REASONS = ['refused'];
// So many events per target and per reading at most (a first scan after a
// change of the firewall can open many ports at once).
const MAX_EVENTS_PER_KIND = 10;

/**
 * @description Keep only the declared keys of an output object.
 * @param {object} values - The values.
 * @param {string[]} keys - The declared keys.
 * @returns {object} The outputs (null / undefined left out).
 */
function pick(values, keys) {
  return Object.fromEntries(
    keys
      .filter((key) => values[key] !== null && values[key] !== undefined)
      .map((key) => [key, values[key]]),
  );
}

/**
 * @description What the triggers remember of a reading.
 * @param {object} reading - The reading.
 * @returns {object} `{ ip, source, ports, vulns, tags }`.
 */
function memoryOf(reading) {
  return {
    ip: reading.ip,
    source: reading.source,
    ports: [...reading.ports],
    vulns: [...reading.vulns],
    tags: [...reading.tags],
  };
}

/**
 * @description The events of a new reading of a target.
 * @param {object|undefined} seen - What the triggers remember (memoryOf), undefined at first.
 * @param {object} reading - The new reading.
 * @returns {{ events: Array<{ key: string, values: object }>, next: object }} The events
 * (`values` the specific data: port, cve, tag) and what to remember.
 */
function detectTarget(seen, reading) {
  const next = memoryOf(reading);
  if (!seen || seen.ip !== reading.ip || seen.source !== reading.source) {
    return { events: [], next };
  }
  const added = (before, after) => after.filter((item) => !before.includes(item));
  const events = [];
  const push = (key, list, values) =>
    list
      .slice(0, MAX_EVENTS_PER_KIND)
      .forEach((item) => events.push({ key, values: values(item) }));
  push(TRIGGERS.PORT_OPENED, added(seen.ports ?? [], next.ports), (port) => ({ port }));
  push(TRIGGERS.PORT_CLOSED, added(next.ports, seen.ports ?? []), (port) => ({ port }));
  push(TRIGGERS.VULNERABILITY_FOUND, added(seen.vulns ?? [], next.vulns), (cve) => ({ cve }));
  push(TRIGGERS.VULNERABILITY_GONE, added(next.vulns, seen.vulns ?? []), (cve) => ({ cve }));
  push(TRIGGERS.TAG_ADDED, added(seen.tags ?? [], next.tags), (tag) => ({ tag }));
  return { events, next };
}

/**
 * @description The data of an event of a target.
 * @param {object} view - `{ deviceId, name, reading }` (app.js).
 * @param {object} event - `{ key, values }` (detectTarget).
 * @returns {object} The flat data of the event.
 */
function targetEventData(view, event) {
  const { reading } = view;
  const data = {
    target: view.deviceId,
    target_name: view.name.slice(0, 200),
    ip: reading.ip,
    ports: portsText(reading, 1000),
  };
  if (event.values.port !== undefined) {
    const service = reading.services.find((item) => item.port === event.values.port);
    data.port = event.values.port;
    data.transport = service?.transport ?? null;
    data.product = service
      ? [service.product, service.version].filter(Boolean).join(' ') || null
      : null;
  }
  if (event.values.cve) {
    data.cve = event.values.cve;
    data.cvss = reading.cvss[event.values.cve] ?? null;
    data.summary = reading.summaries[event.values.cve]?.slice(0, 1000) ?? null;
    data.url = `https://nvd.nist.gov/vuln/detail/${event.values.cve}`;
  }
  if (event.values.tag) {
    data.tag = event.values.tag;
  }
  return data;
}

/**
 * @description The outputs every action shares, from a reading.
 * @param {object} reading - The reading.
 * @param {string} language - The language.
 * @returns {object} The values.
 */
function readingOutputs(reading, language) {
  const list = (items) => items.join(', ').slice(0, 10000);
  return {
    ip: reading.ip,
    port_count: reading.ports.length,
    ports: portsText(reading, 10000),
    vuln_count: reading.vulns.length,
    vulns: list(reading.vulns),
    max_cvss: maxCvss(reading),
    tags: list(reading.tags),
    hostnames: list(reading.hostnames),
    source: reading.source,
    summary: summaryText(reading, language),
  };
}

/**
 * @description A sentence of a reading, for a message.
 * @param {object} reading - The reading.
 * @param {string} language - The language.
 * @param {string} [name] - The name of the target.
 * @returns {string} "home: 2 open ports (22/tcp, 443/tcp), 1 vulnerability."
 */
function summaryText(reading, language, name) {
  const who = name ? `${name} (${reading.ip})` : reading.ip;
  if (!reading.found || reading.ports.length === 0) {
    return t('summaryNothing', language, { who }).slice(0, 1000);
  }
  return [
    tn('summaryPorts', reading.ports.length, language, { who, ports: portsText(reading, 300) }),
    reading.vulns.length
      ? tn('summaryVulns', reading.vulns.length, language, {
          max: Number.isFinite(maxCvss(reading)) ? ` (CVSS ${maxCvss(reading)})` : '',
        })
      : t('summaryNoVulns', language),
    ...(reading.tags.length ? [t('summaryTags', language, { tags: reading.tags.join(', ') })] : []),
  ]
    .join(' ')
    .slice(0, 1000);
}

export {
  TRIGGERS,
  SCENE_ACTIONS,
  TARGET_OUTPUTS,
  LOOKUP_OUTPUTS,
  SCAN_OUTPUTS,
  TAGS,
  ACCESS_REASONS,
  MAX_EVENTS_PER_KIND,
  pick,
  memoryOf,
  detectTarget,
  targetEventData,
  readingOutputs,
  summaryText,
};
