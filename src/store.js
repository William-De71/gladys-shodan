// -----------------------------------------------------------------------------
// What the integration keeps across restarts, under /data (the only writable
// place of the container), in /data/shodan.json (mode 0600):
//
//   - `targets`        per target id (`public`, or the address typed): the
//                      address read (`ip`), the last reading (parse.js),
//                      `readAt` when it succeeded, `triedAt` the last try,
//                      `error` the last error ({ kind, detail }) or null;
//   - `publicIp`       the public address of the home, `checkedAt` its last check;
//   - `seen`           what the scene triggers know, per target;
//   - `apiInfo`        the plan and credits of the key, `apiInfoAt`;
//   - `hostDeniedUntil` until when the host lookups of the API are not tried
//                      again after a refusal of the plan (403): InternetDB
//                      answers meanwhile;
//   - `scans`          the on-demand scans asked (id, address, status);
//   - `accessRefused`  why Shodan refuses the key, or null (the trigger fires
//                      once per refusal);
//   - `lastError`      the last error (diagnostic).
// Never the API key.
// -----------------------------------------------------------------------------

import { readFile, writeFile, rename, mkdir, chmod } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const DEFAULT_DIR = '/data';
const FILE = 'shodan.json';
const EMPTY = () => ({
  targets: {},
  publicIp: null,
  publicIpCheckedAt: 0,
  seen: {},
  apiInfo: null,
  apiInfoAt: 0,
  hostDeniedUntil: 0,
  scans: [],
  accessRefused: null,
  lastError: null,
});

/**
 * @description Read a JSON file; an absent or broken file is null.
 * @param {string} path - The file.
 * @param {object} [logger] - Logger.
 * @returns {Promise<object|null>} The value.
 */
async function readJson(path, logger) {
  try {
    const value = JSON.parse(await readFile(path, 'utf8'));
    return value && typeof value === 'object' ? value : null;
  } catch (err) {
    if (err.code !== 'ENOENT') {
      logger?.warn(`Unable to read ${path}: ${err.message}`);
    }
    return null;
  }
}

/**
 * @description Write a JSON file atomically (a temporary file, then a
 * rename), readable by its owner only.
 * @param {string} path - The file.
 * @param {object} value - The value.
 * @param {object} [logger] - Logger.
 * @returns {Promise<void>}
 */
async function writeJson(path, value, logger) {
  try {
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.tmp`;
    await writeFile(temporary, JSON.stringify(value), { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, path);
  } catch (err) {
    logger?.warn(`Unable to write ${path}: ${err.message}`);
  }
}

const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const finite = (value) => (Number.isFinite(value) ? value : 0);

/**
 * @description The store.
 * @param {object} [options] - `{ dir, logger }`.
 * @returns {object} `{ data, load, save, reset, path }`.
 */
function createStore({ dir = DEFAULT_DIR, logger } = {}) {
  const path = join(dir, FILE);
  let writing = Promise.resolve();
  const store = {
    path,
    data: EMPTY(),
    /**
     * @description Read the file.
     * @returns {Promise<void>}
     */
    async load() {
      const raw = (await readJson(path, logger)) ?? {};
      const data = EMPTY();
      data.targets = isObject(raw.targets)
        ? Object.fromEntries(
            Object.entries(raw.targets).filter(
              ([, target]) =>
                isObject(target) && (target.reading === null || isObject(target.reading)),
            ),
          )
        : {};
      data.publicIp = typeof raw.publicIp === 'string' ? raw.publicIp : null;
      data.publicIpCheckedAt = finite(raw.publicIpCheckedAt);
      data.seen = isObject(raw.seen) ? { ...raw.seen } : {};
      data.apiInfo = isObject(raw.apiInfo) ? raw.apiInfo : null;
      data.apiInfoAt = finite(raw.apiInfoAt);
      data.hostDeniedUntil = finite(raw.hostDeniedUntil);
      data.scans = Array.isArray(raw.scans) ? raw.scans.filter(isObject).slice(-10) : [];
      data.accessRefused = isObject(raw.accessRefused) ? raw.accessRefused : null;
      data.lastError = isObject(raw.lastError) ? raw.lastError : null;
      store.data = data;
    },
    /**
     * @description Forget everything.
     */
    reset() {
      store.data = EMPTY();
    },
    /**
     * @description Write the state (one write at a time).
     * @returns {Promise<void>}
     */
    save() {
      writing = writing.then(() => writeJson(path, store.data, logger));
      return writing;
    },
  };
  return store;
}

export { DEFAULT_DIR, FILE, createStore };
