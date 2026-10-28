// -----------------------------------------------------------------------------
// The answers of Shodan made safe, and the addresses the user typed.
//
// A reading of an address is one shape whatever its source:
//   {
//     ip, source: 'internetdb' | 'api', found,
//     ports: [22, 443],                      sorted, unique
//     vulns: ['CVE-2023-38408', …],          sorted, unique, upper case
//     cvss: { 'CVE-…': 9.8 },                API only: the score Shodan gives
//     summaries: { 'CVE-…': '…' },           API only, clipped
//     services: [{ port, transport, product, version }],   API only
//     hostnames, tags, cpes,
//     org, isp, os, lastUpdate (ms),         API only
//   }
// `found: false` is an address Shodan knows nothing about (404): nothing
// exposed as far as Shodan can tell, never an error.
// -----------------------------------------------------------------------------

import { isIP } from 'node:net';

const MAX_ADDRESSES = 10;
const MAX_LIST = 200;
const MAX_TEXT = 200;
const CVE = /^CVE-\d{4}-\d{4,}$/;

const text = (value, max = MAX_TEXT) =>
  typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : null;

/**
 * @description A sorted list of unique strings.
 * @param {unknown} value - The list.
 * @param {Function} [keep] - `(text) => boolean`.
 * @returns {string[]} The list.
 */
function strings(value, keep = () => true) {
  if (!Array.isArray(value)) return [];
  const list = value.map((item) => text(item, 120)).filter((item) => item && keep(item));
  return [...new Set(list)].sort().slice(0, MAX_LIST);
}

/**
 * @description A sorted list of unique port numbers.
 * @param {unknown} value - The list.
 * @returns {number[]} The ports.
 */
function portList(value) {
  if (!Array.isArray(value)) return [];
  const list = value
    .map(Number)
    .filter((port) => Number.isInteger(port) && port > 0 && port < 65536);
  return [...new Set(list)].sort((a, b) => a - b).slice(0, MAX_LIST);
}

/**
 * @description CVE ids, upper case, sorted.
 * @param {unknown} value - A list of ids, or an object keyed by id.
 * @returns {string[]} The ids.
 */
function cveList(value) {
  const list = Array.isArray(value)
    ? value
    : value && typeof value === 'object'
      ? Object.keys(value)
      : [];
  return strings(
    list.map((item) => (typeof item === 'string' ? item.toUpperCase() : item)),
    (id) => CVE.test(id),
  );
}

/**
 * @description An instant of Shodan ("2026-10-27T12:34:56.123456", UTC without a zone).
 * @param {unknown} value - The text.
 * @returns {number|null} The instant (ms).
 */
function shodanTime(value) {
  const raw = text(value, 40);
  if (!raw) return null;
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : `${raw.replace(/(\.\d{3})\d+/, '$1')}Z`;
  const instant = Date.parse(iso);
  return Number.isFinite(instant) ? instant : null;
}

/**
 * @description The empty reading of an address Shodan knows nothing about.
 * @param {string} ip - The address.
 * @param {string} source - `internetdb` or `api`.
 * @returns {object} The reading.
 */
function notFound(ip, source) {
  return {
    ip,
    source,
    found: false,
    ports: [],
    vulns: [],
    cvss: {},
    summaries: {},
    services: [],
    hostnames: [],
    tags: [],
    cpes: [],
    org: null,
    isp: null,
    os: null,
    lastUpdate: null,
  };
}

/**
 * @description An answer of InternetDB.
 * @param {object} body - `{ ip, ports, cpes, hostnames, tags, vulns }`.
 * @param {string} ip - The address asked.
 * @returns {object} The reading.
 */
function parseInternetDb(body, ip) {
  return {
    ...notFound(text(body?.ip, 64) ?? ip, 'internetdb'),
    found: true,
    ports: portList(body?.ports),
    vulns: cveList(body?.vulns),
    hostnames: strings(body?.hostnames),
    tags: strings(body?.tags),
    cpes: strings(body?.cpes),
  };
}

/**
 * @description An answer of /shodan/host/{ip}.
 * @param {object} body - The host.
 * @param {string} ip - The address asked.
 * @returns {object} The reading.
 */
function parseHost(body, ip) {
  const data = Array.isArray(body?.data)
    ? body.data.filter((item) => item && typeof item === 'object')
    : [];
  const cvss = {};
  const summaries = {};
  const services = [];
  for (const item of data) {
    const port = portList([item.port])[0];
    if (port) {
      services.push({
        port,
        transport: text(item.transport, 8) ?? 'tcp',
        product: text(item.product, 80),
        version: text(item.version, 40),
        vulns: cveList(item.vulns),
      });
    }
    if (item.vulns && typeof item.vulns === 'object' && !Array.isArray(item.vulns)) {
      for (const [id, details] of Object.entries(item.vulns)) {
        const key = id.toUpperCase();
        const score = Number(details?.cvss);
        if (CVE.test(key) && Number.isFinite(score) && score >= 0 && score <= 10) {
          cvss[key] = Math.max(cvss[key] ?? 0, score);
        }
        const summary = text(details?.summary, 600);
        if (CVE.test(key) && summary && !summaries[key]) summaries[key] = summary;
      }
    }
  }
  const unique = new Map();
  for (const service of services) {
    unique.set(`${service.port}/${service.transport}`, service);
  }
  const vulns = cveList([...cveList(body?.vulns), ...services.flatMap((service) => service.vulns)]);
  return {
    ...notFound(text(body?.ip_str, 64) ?? ip, 'api'),
    found: true,
    ports: portList([
      ...(Array.isArray(body?.ports) ? body.ports : []),
      ...services.map((s) => s.port),
    ]),
    vulns,
    cvss,
    summaries,
    services: [...unique.values()]
      .sort((a, b) => a.port - b.port || a.transport.localeCompare(b.transport))
      .slice(0, MAX_LIST),
    hostnames: strings(body?.hostnames),
    tags: strings(body?.tags),
    cpes: strings(data.flatMap((item) => (Array.isArray(item.cpe23) ? item.cpe23 : []))),
    org: text(body?.org, 120),
    isp: text(body?.isp, 120),
    os: text(body?.os, 80),
    lastUpdate: shodanTime(body?.last_update),
  };
}

/**
 * @description An answer of /api-info.
 * @param {object} body - The answer.
 * @returns {object} `{ plan, queryCredits, scanCredits, monitoredIps, limits }`.
 */
function parseApiInfo(body) {
  const count = (value) =>
    Number.isFinite(Number(value)) && value !== null ? Number(value) : null;
  const limits = body?.usage_limits ?? {};
  return {
    plan: text(body?.plan, 40),
    queryCredits: count(body?.query_credits),
    scanCredits: count(body?.scan_credits),
    monitoredIps: count(body?.monitored_ips),
    limits: {
      queryCredits: count(limits.query_credits),
      scanCredits: count(limits.scan_credits),
      monitoredIps: count(limits.monitored_ips),
    },
  };
}

/**
 * @description The highest CVSS score of a reading.
 * @param {object} reading - The reading.
 * @returns {number|null} The score, null when unknown.
 */
function maxCvss(reading) {
  const scores = Object.values(reading?.cvss ?? {}).filter(Number.isFinite);
  return scores.length ? Math.max(...scores) : null;
}

/**
 * @description The ports of a reading as a text: "22/tcp, 443/tcp" (API) or "22, 443".
 * @param {object} reading - The reading.
 * @param {number} [max] - Characters at most.
 * @returns {string} The text, '' when none.
 */
function portsText(reading, max = MAX_TEXT) {
  const transports = new Map();
  for (const service of reading?.services ?? []) {
    if (!transports.has(service.port)) transports.set(service.port, service.transport);
  }
  const list = (reading?.ports ?? []).map((port) =>
    transports.has(port) ? `${port}/${transports.get(port)}` : String(port),
  );
  const whole = list.join(', ');
  return whole.length > max ? `${whole.slice(0, max - 1)}…` : whole;
}

// --- Addresses ---------------------------------------------------------------------

/**
 * @description Whether an IPv4 address is reachable from the Internet.
 * @param {string} ip - The address.
 * @returns {boolean} False for private, loopback, link-local, shared, reserved.
 */
function isPublicIpv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

/**
 * @description Whether an address is a public one, the only kind Shodan scans.
 * @param {string} ip - The address.
 * @returns {boolean} True when public.
 */
function isPublicIp(ip) {
  const value = String(ip ?? '');
  const version = isIP(value);
  if (version === 4) return isPublicIpv4(value);
  if (version !== 6) return false;
  const lower = value.toLowerCase();
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPublicIpv4(mapped[1]);
  // Global unicast only (2000::/3): no loopback, link-local, unique local, multicast.
  return /^[23][0-9a-f]{0,3}:/.test(lower) && !lower.startsWith('2001:db8:');
}

const HOSTNAME =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/**
 * @description The addresses the user typed: IP addresses or host names,
 * separated by commas, semicolons, spaces or new lines.
 * @param {unknown} value - The text.
 * @returns {{ addresses: Array<{ address: string, kind: string }>, rejected: string[] }}
 * `kind` is `ip` or `host`; `rejected` the entries that are neither, or private.
 */
function parseAddresses(value) {
  const addresses = [];
  const rejected = [];
  const seen = new Set();
  const entries = String(value ?? '')
    .split(/[\s,;]+/)
    .map((entry) => entry.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);
  for (const entry of entries) {
    if (seen.has(entry)) continue;
    seen.add(entry);
    if (isIP(entry)) {
      if (isPublicIp(entry)) addresses.push({ address: entry, kind: 'ip' });
      else rejected.push(entry);
    } else if (HOSTNAME.test(entry) && !entry.endsWith('.local') && !entry.endsWith('.lan')) {
      addresses.push({ address: entry, kind: 'host' });
    } else {
      rejected.push(entry.slice(0, 64));
    }
  }
  return { addresses: addresses.slice(0, MAX_ADDRESSES), rejected };
}

export {
  MAX_ADDRESSES,
  shodanTime,
  notFound,
  parseInternetDb,
  parseHost,
  parseApiInfo,
  maxCvss,
  portsText,
  isPublicIp,
  parseAddresses,
};
