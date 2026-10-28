// -----------------------------------------------------------------------------
// HTTP client of the two official Shodan services:
//
//   InternetDB (https://internetdb.shodan.io), no key, free for non-commercial
//   use, refreshed once a week (its CDN keeps an answer up to 5 days):
//     GET /{ip}   -> { ip, ports, cpes, hostnames, tags, vulns }
//                    404 {"detail":"No information available"}: nothing known
//
//   The Shodan API (https://api.shodan.io, https://developer.shodan.io/api),
//   with the key of a Shodan account (`?key=`):
//     GET  /tools/myip          -> "82.66.249.84" (the address the request comes from)
//     GET  /shodan/host/{ip}    -> the host and its services (`data[]`); 404
//                                  {"error":"No information available for that IP."}
//     GET  /api-info            -> plan, query / scan credits, usage limits
//     POST /shodan/scan         form ips=… -> { id, count, credits_left }
//                                  (scan credits: a paid plan)
//     GET  /shodan/scan/{id}    -> { id, status: SUBMITTING | QUEUE | PROCESSING | DONE }
//
// Answers seen live (2026-10-28): a wrong key gets 401 and an HTML page on
// every endpoint but /tools/myip, which answers without a valid key (and
// without any key: the address is then asked without one, an undocumented
// use kept for the instances without a key); a private address gets 404
// {"error":"Invalid IP"}.
//
// Shodan asks for one request a second at most: the client sends one request
// at a time, 1.1 s apart, and pauses one service (not the other) after a 429
// (the Retry-After, else 10 minutes), a 5xx or no answer (5 minutes doubling
// up to 2 hours). The key travels in the URL, as the API wants it: it is
// never logged (`endpoint` in the errors is the path without the query).
// -----------------------------------------------------------------------------

const API_URL = 'https://api.shodan.io';
const INTERNETDB_URL = 'https://internetdb.shodan.io';
const TIMEOUT_MS = 30000;
const SPACING_MS = 1100;
const RATE_LIMIT_PAUSE_MS = 10 * 60 * 1000;
const MIN_PAUSE_MS = 5 * 60 * 1000;
const MAX_PAUSE_MS = 2 * 60 * 60 * 1000;

/**
 * @description An error of a Shodan service.
 */
class ShodanError extends Error {
  /**
   * @param {string} kind - `auth` (key refused), `plan` (the plan does not
   * allow it), `not_found`, `invalid` (an address Shodan refuses),
   * `rate_limit`, `server`, `http`, `unreachable`, `failed`.
   * @param {string} message - What went wrong (never the key).
   * @param {object} [extra] - `{ status, endpoint, detail, retryAfter, service }`.
   */
  constructor(kind, message, extra = {}) {
    super(message);
    this.name = 'ShodanError';
    this.kind = kind;
    Object.assign(this, extra);
  }
}

/**
 * @description The seconds of a Retry-After header (a number or an HTTP date).
 * @param {string|null} header - The header.
 * @param {number} now - Now (ms).
 * @returns {number|null} Seconds, null when absent or unreadable.
 */
function retryAfterSeconds(header, now) {
  if (header === null || header === undefined || header === '') {
    return null;
  }
  const seconds = Number(header);
  if (Number.isFinite(seconds)) {
    return Math.max(0, seconds);
  }
  const date = Date.parse(header);
  return Number.isFinite(date) ? Math.max(0, Math.round((date - now) / 1000)) : null;
}

/**
 * @description The Shodan client.
 * @param {object} options - Options.
 * @param {Function} options.getKey - `() => string` the API key ('' when none).
 * @param {string} options.userAgent - The User-Agent of every request.
 * @param {Function} [options.fetch] - The fetch implementation (tests).
 * @param {string} [options.apiUrl] - The API root (tests).
 * @param {string} [options.internetDbUrl] - The InternetDB root (tests).
 * @param {Function} [options.now] - `() => number` in ms.
 * @param {Function} [options.sleep] - `(ms) => Promise` (tests).
 * @returns {object} The client.
 */
function createShodanClient({
  getKey,
  userAgent,
  fetch: fetchFn = globalThis.fetch,
  apiUrl = API_URL,
  internetDbUrl = INTERNETDB_URL,
  now = () => Date.now(),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  let chain = Promise.resolve();
  let lastRequestEnd = -Infinity;
  const services = {
    api: { root: apiUrl, pausedUntil: 0, failures: 0 },
    internetdb: { root: internetDbUrl, pausedUntil: 0, failures: 0 },
  };
  let requests = 0;

  /**
   * @description Run a function in the queue: one request at a time.
   * @param {Function} run - `() => Promise`.
   * @returns {Promise<*>} Its result.
   */
  function queued(run) {
    const result = chain.then(run);
    chain = result.catch(() => {});
    return result;
  }

  /**
   * @description Pause a service after a failure.
   * @param {object} service - `services.api` or `services.internetdb`.
   * @param {number} [base] - The first pause (ms).
   * @param {number|null} [retryAfter] - Seconds asked by the service.
   */
  function pause(service, base = MIN_PAUSE_MS, retryAfter = null) {
    service.failures += 1;
    const backoff = base * 2 ** Math.min(service.failures - 1, 4);
    const asked = Number.isFinite(retryAfter) ? retryAfter * 1000 : 0;
    service.pausedUntil = Math.max(
      service.pausedUntil,
      now() + Math.min(Math.max(backoff, asked, base), MAX_PAUSE_MS),
    );
  }

  /**
   * @description The `error` / `detail` text of an answer, without the key.
   * @param {object|null} body - The answer.
   * @returns {string} The text ('' when none).
   */
  function detailOf(body) {
    const text = typeof body?.error === 'string' ? body.error : body?.detail;
    return typeof text === 'string' ? text.slice(0, 200) : '';
  }

  /**
   * @description Send a request, spaced from the previous one.
   * @param {string} name - `api` or `internetdb`.
   * @param {string} path - The path, without the query.
   * @param {object} [options] - `{ method, query, form, withKey }`.
   * @returns {Promise<{ status: number, body: * }>} The answer (JSON, or null).
   */
  async function send(name, path, { method = 'GET', query = {}, form, withKey = false } = {}) {
    const service = services[name];
    if (service.pausedUntil > now()) {
      throw new ShodanError('rate_limit', `${name} paused after errors`, {
        endpoint: path,
        service: name,
        retryAfter: Math.ceil((service.pausedUntil - now()) / 1000),
      });
    }
    const params = new URLSearchParams(query);
    if (withKey) {
      params.set('key', getKey());
    }
    const search = params.toString();
    const wait = lastRequestEnd + SPACING_MS - now();
    if (wait > 0) {
      await sleep(wait);
    }
    requests += 1;
    let response;
    let text;
    try {
      response = await fetchFn(`${service.root}${path}${search ? `?${search}` : ''}`, {
        method,
        headers: {
          'user-agent': userAgent,
          accept: 'application/json',
          ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
        },
        ...(form ? { body: new URLSearchParams(form).toString() } : {}),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      text = await response.text().catch(() => '');
    } catch (err) {
      pause(service);
      // The message of a fetch error may carry the URL, hence the key: never kept.
      throw new ShodanError('unreachable', `${name} unreachable (${err.name})`, {
        endpoint: path,
        service: name,
      });
    } finally {
      lastRequestEnd = now();
    }
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
    const status = response.status;
    const extra = { status, endpoint: path, service: name, detail: detailOf(body) };
    if (status === 429) {
      pause(
        service,
        RATE_LIMIT_PAUSE_MS,
        retryAfterSeconds(response.headers.get('retry-after'), now()),
      );
      throw new ShodanError('rate_limit', `HTTP 429 on ${path}`, extra);
    }
    if (status >= 500) {
      pause(service);
      throw new ShodanError('server', `HTTP ${status} on ${path}`, extra);
    }
    service.failures = 0;
    if (status === 401) {
      throw new ShodanError('auth', `Shodan refused the API key (HTTP 401)`, extra);
    }
    if (status === 403) {
      throw new ShodanError('plan', `Shodan refused the request (HTTP 403)`, extra);
    }
    if (status === 404 && /invalid ip/i.test(extra.detail)) {
      throw new ShodanError('invalid', `Shodan refuses this address`, extra);
    }
    if (status === 404) {
      throw new ShodanError('not_found', `Nothing known (HTTP 404 on ${path})`, extra);
    }
    if (status === 400) {
      throw new ShodanError('invalid', `HTTP 400 on ${path}`, extra);
    }
    if (status < 200 || status >= 300) {
      throw new ShodanError('http', `HTTP ${status} on ${path}`, extra);
    }
    return { status, body };
  }

  const hasKey = () => Boolean(getKey());

  /**
   * @description A request that needs the key.
   * @param {string} path - The path.
   * @param {object} [options] - `send` options.
   * @returns {Promise<*>} The body.
   */
  function withKey(path, options = {}) {
    return queued(async () => {
      if (!hasKey()) {
        throw new ShodanError('auth', 'No Shodan API key', { endpoint: path, code: 'missing' });
      }
      return (await send('api', path, { ...options, withKey: true })).body;
    });
  }

  return {
    hasKey,
    /**
     * @description The public address the requests come from.
     * @returns {Promise<string>} The address.
     */
    myIp: () =>
      queued(async () => {
        const { body } = await send('api', '/tools/myip', { withKey: hasKey() });
        if (typeof body !== 'string' || !body.trim()) {
          throw new ShodanError('failed', 'Unexpected answer of /tools/myip', {
            endpoint: '/tools/myip',
          });
        }
        return body.trim();
      }),
    /**
     * @description What InternetDB knows of an address (no key).
     * @param {string} ip - The address.
     * @returns {Promise<object>} The answer.
     */
    internetDb: (ip) =>
      queued(async () => {
        const path = `/${encodeURIComponent(ip)}`;
        const { body } = await send('internetdb', path);
        if (!body || typeof body !== 'object') {
          throw new ShodanError('failed', 'Unexpected answer of InternetDB', { endpoint: path });
        }
        return body;
      }),
    /**
     * @description What the Shodan API knows of a host (key).
     * @param {string} ip - The address.
     * @returns {Promise<object>} The answer.
     */
    host: (ip) => withKey(`/shodan/host/${encodeURIComponent(ip)}`),
    /**
     * @description The plan and the credits of the key.
     * @returns {Promise<object>} The answer.
     */
    apiInfo: () => withKey('/api-info'),
    /**
     * @description Ask Shodan to scan an address (1 scan credit).
     * @param {string} ip - The address.
     * @returns {Promise<object>} `{ id, count, credits_left }`.
     */
    scan: (ip) => withKey('/shodan/scan', { method: 'POST', form: { ips: ip } }),
    /**
     * @description The state of a scan.
     * @param {string} id - The scan id.
     * @returns {Promise<object>} `{ id, status }`.
     */
    scanStatus: (id) => withKey(`/shodan/scan/${encodeURIComponent(id)}`),
    /**
     * @description Until when a service pauses after errors (0: not paused).
     * @param {string} [name] - `api` or `internetdb`; the later of both by default.
     * @returns {number} The instant (ms).
     */
    pausedUntil(name) {
      const list = name ? [services[name]] : Object.values(services);
      const until = Math.max(...list.map((service) => service.pausedUntil));
      return until > now() ? until : 0;
    },
    /**
     * @description How many requests were sent since the start.
     * @returns {{ requests: number }} The count.
     */
    counts: () => ({ requests }),
  };
}

export {
  API_URL,
  INTERNETDB_URL,
  SPACING_MS,
  RATE_LIMIT_PAUSE_MS,
  MIN_PAUSE_MS,
  MAX_PAUSE_MS,
  ShodanError,
  retryAfterSeconds,
  createShodanClient,
};
