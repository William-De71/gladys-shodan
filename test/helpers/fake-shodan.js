// -----------------------------------------------------------------------------
// A fake Shodan for the tests: an in-memory `fetch` (no network) answering
// like InternetDB and the Shodan API (the documentation and the answers seen
// live on 2026-10-28):
//   - InternetDB GET /{ip}: the fixture, else 404 {"detail":"No information available"};
//   - API with a wrong key: 401 and an HTML page (every endpoint but /tools/myip);
//   - GET /tools/myip: the public address, as a JSON string, key or not;
//   - GET /shodan/host/{ip}: the fixture; 404 {"error":"No information
//     available for that IP."}; a private address 404 {"error":"Invalid IP"};
//     403 when `planDenied`;
//   - GET /api-info, POST /shodan/scan (form ips), GET /shodan/scan/{id}.
// Every call is recorded with the clock of the test (the key masked).
// Nothing starts on import (node --test also runs test/helpers/).
// -----------------------------------------------------------------------------

import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * @description A temporary folder standing for /data.
 * @returns {string} The path.
 */
const dataDir = () => mkdtempSync(join(tmpdir(), 'gladys-shodan-'));

/**
 * @description A logger that keeps every line (to check what is never logged).
 * @returns {object} The logger, with `lines`.
 */
function recordingLogger() {
  const lines = [];
  const keep =
    (level) =>
    (...args) =>
      lines.push(
        `${level} ${args.map((arg) => (arg instanceof Error ? arg.stack : String(arg))).join(' ')}`,
      );
  return {
    lines,
    debug: keep('debug'),
    info: keep('info'),
    warn: keep('warn'),
    error: keep('error'),
  };
}

const API = 'https://api.shodan.test';
const INTERNETDB = 'https://internetdb.shodan.test';
const KEY = 'not-a-real-shodan-key';
const fixture = () =>
  JSON.parse(readFileSync(new URL('../fixtures/hosts.json', import.meta.url), 'utf8'));

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
const html = (status) =>
  new Response(`<html><title>${status}</title></html>`, {
    status,
    headers: { 'content-type': 'text/html' },
  });

/**
 * @description The fake Shodan.
 * @param {object} [options] - `{ clock }`: `{ now }` in ms.
 * @returns {object} The fake.
 */
function createFakeShodan({ clock = { now: Date.now() } } = {}) {
  const data = fixture();
  const fake = {
    clock,
    apiUrl: API,
    internetDbUrl: INTERNETDB,
    key: KEY,
    publicIp: '203.0.113.7',
    internetdb: data.internetdb,
    hosts: data.api,
    apiInfo: data.apiInfo,
    planDenied: false,
    down: new Set(),
    rateLimited: new Set(),
    scans: new Map(),
    calls: [],
    /**
     * @description The calls to a path (or a regular expression).
     * @param {string|RegExp} path - The path.
     * @returns {object[]} The calls.
     */
    callsTo(path) {
      return fake.calls.filter((call) =>
        path instanceof RegExp ? path.test(call.path) : call.path === path,
      );
    },
    /**
     * @description The fetch.
     * @param {string} url - The URL.
     * @param {object} [init] - The options.
     * @returns {Promise<Response>} The answer.
     */
    async fetch(url, init = {}) {
      const parsed = new URL(url);
      const service = parsed.origin === API ? 'api' : 'internetdb';
      const key = parsed.searchParams.get('key');
      fake.calls.push({
        service,
        path: parsed.pathname,
        method: init.method ?? 'GET',
        key,
        body: init.body,
        userAgent: init.headers?.['user-agent'],
        at: fake.clock.now,
      });
      if (fake.down.has(service)) {
        throw new TypeError(`fetch failed ${url}`);
      }
      if (fake.rateLimited.has(service)) {
        return json(429, { error: 'Rate limit reached' }, { 'retry-after': '120' });
      }
      if (service === 'internetdb') {
        const ip = decodeURIComponent(parsed.pathname.slice(1));
        return fake.internetdb[ip]
          ? json(200, fake.internetdb[ip])
          : json(404, { detail: 'No information available' });
      }
      if (parsed.pathname === '/tools/myip') {
        return json(200, fake.publicIp);
      }
      if (key !== fake.key) {
        return html(401);
      }
      const host = parsed.pathname.match(/^\/shodan\/host\/(.+)$/);
      if (host) {
        const ip = decodeURIComponent(host[1]);
        if (/^(10|192\.168|127)\./.test(ip)) return json(404, { error: 'Invalid IP' });
        if (fake.planDenied) return json(403, { error: 'Access denied (403 Forbidden)' });
        return fake.hosts[ip]
          ? json(200, fake.hosts[ip])
          : json(404, { error: 'No information available for that IP.' });
      }
      if (parsed.pathname === '/api-info') {
        return json(200, fake.apiInfo);
      }
      if (parsed.pathname === '/shodan/scan' && init.method === 'POST') {
        if (!fake.apiInfo.scan_credits) {
          return json(403, { error: 'Insufficient scan credits, please help support Shodan.' });
        }
        const ips = new URLSearchParams(init.body).get('ips');
        const id = `SCAN${fake.scans.size + 1}`;
        fake.scans.set(id, { ips, status: 'QUEUE' });
        fake.apiInfo.scan_credits -= 1;
        return json(200, { id, count: 1, credits_left: fake.apiInfo.scan_credits });
      }
      const scan = parsed.pathname.match(/^\/shodan\/scan\/(.+)$/);
      if (scan && fake.scans.has(scan[1])) {
        return json(200, { id: scan[1], count: 1, status: fake.scans.get(scan[1]).status });
      }
      return json(404, { error: 'Not found' });
    },
  };
  return fake;
}

export { createFakeShodan, dataDir, recordingLogger, KEY };
