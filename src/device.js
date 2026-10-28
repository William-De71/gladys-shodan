// -----------------------------------------------------------------------------
// The devices of the integration, offered on the Discovery screen.
//
// One device per watched address ("target"):
//   - `public`         the public address of the home (the address the
//                      requests leave from: it may change, the device stays);
//   - an address typed in the configuration, an IP address or a host name
//     (resolved at each reading).
// Read only. Category / type pairs from the Gladys core (master 2026-10-26):
//   - `open_ports`       counter-sensor / integer: the ports Shodan saw open;
//   - `vulnerabilities`  counter-sensor / integer: the CVE Shodan matched to
//                        the software it saw (not verified on the machine);
//   - `ip`               text / text: the address read (the public address
//                        of the home, or the one a host name resolves to);
//   - `ports`            text / text: "22/tcp, 443/tcp" (or "22, 443").
// External ids: `ext:<selector>:target:public` and
// `ext:<selector>:target:<address>`, every character outside [A-Za-z0-9_-]
// replaced by "-" (`home-example-org`, `203-0-113-7`). `should_poll` stays
// false: the integration reads Shodan on its own timer.
// -----------------------------------------------------------------------------

import {
  DEVICE_FEATURE_CATEGORIES as C,
  DEVICE_FEATURE_TYPES as T,
} from '@gladysassistant/integration-sdk';
import { t } from './i18n.js';
import { portsText } from './parse.js';

const TARGET_TYPE = 'target';
const PUBLIC_ID = 'public';
const MAX_PORTS = 65535;
const MAX_VULNS = 10000;
const FEATURE_KEYS = ['open_ports', 'vulnerabilities', 'ip', 'ports'];

/**
 * @description The platform id of a target, safe for an external id.
 * @param {object} target - `{ id }` of a target (`public`, or the address).
 * @returns {string} The id.
 */
const platformId = (target) =>
  String(target?.id ?? '')
    .replace(/[^A-Za-z0-9_-]/g, '-')
    .slice(0, 64);

/**
 * @description The external ids of a target.
 * @param {object} gladys - The GladysIntegration instance.
 * @param {object} target - The target.
 * @returns {{ device: string, feature: Function }} The ids.
 */
const targetIds = (gladys, target) => gladys.externalIds(TARGET_TYPE, platformId(target));

/**
 * @description The platform id of a target device external id (or of one of its features).
 * @param {unknown} externalId - `ext:…:target:public` (or `…:open_ports`).
 * @returns {string|null} The platform id.
 */
function targetOfExternalId(externalId) {
  const match = String(externalId ?? '').match(/:target:([A-Za-z0-9_-]+)(?::[a-z_]+)?$/);
  return match ? match[1] : null;
}

/**
 * @description The default name of a target.
 * @param {object} target - The target.
 * @param {string} language - The language.
 * @returns {string} "Shodan: public IP", "Shodan home.example.org".
 */
const defaultName = (target, language) =>
  target.id === PUBLIC_ID ? t('namePublic', language) : `Shodan ${target.address}`;

/**
 * @description The features of a target.
 * @returns {object[]} `{ key, category, type, unit, min, max }`.
 */
function featuresOf() {
  return [
    {
      key: 'open_ports',
      category: C.COUNTER_SENSOR,
      type: T.SENSOR.INTEGER,
      unit: null,
      min: 0,
      max: MAX_PORTS,
    },
    {
      key: 'vulnerabilities',
      category: C.COUNTER_SENSOR,
      type: T.SENSOR.INTEGER,
      unit: null,
      min: 0,
      max: MAX_VULNS,
    },
    { key: 'ip', category: C.TEXT, type: T.TEXT.TEXT, unit: null, min: 0, max: 0 },
    { key: 'ports', category: C.TEXT, type: T.TEXT.TEXT, unit: null, min: 0, max: 0 },
  ];
}

/**
 * @description Build the device of a target.
 * @param {object} gladys - The GladysIntegration instance.
 * @param {object} target - The target.
 * @param {object} [options] - `{ language }`.
 * @returns {object} The discovered device.
 */
function buildTargetDevice(gladys, target, { language = 'en' } = {}) {
  const ids = targetIds(gladys, target);
  return {
    name: defaultName(target, language),
    external_id: ids.device,
    model: 'Shodan',
    should_poll: false,
    params: [
      { name: 'SHODAN_TARGET', value: target.id === PUBLIC_ID ? PUBLIC_ID : target.address },
    ],
    features: featuresOf().map((feature) => ({
      name: t(`feature_${feature.key}`, language),
      external_id: ids.feature(feature.key),
      category: feature.category,
      type: feature.type,
      unit: feature.unit,
      min: feature.min,
      max: feature.max,
      read_only: true,
      has_feedback: false,
      keep_history: true,
    })),
  };
}

/**
 * @description The states of a target, from its last reading.
 * @param {object} gladys - The GladysIntegration instance.
 * @param {object} target - The target.
 * @param {object|null} reading - The reading (parse.js), null when none yet.
 * @param {object} [options] - `{ language }`.
 * @returns {object[]} `{ device_feature_external_id, state | text }`.
 */
function buildTargetStates(gladys, target, reading, { language = 'en' } = {}) {
  if (!reading) {
    return [];
  }
  const ids = targetIds(gladys, target);
  return [
    {
      device_feature_external_id: ids.feature('open_ports'),
      state: Math.min(MAX_PORTS, reading.ports.length),
    },
    {
      device_feature_external_id: ids.feature('vulnerabilities'),
      state: Math.min(MAX_VULNS, reading.vulns.length),
    },
    { device_feature_external_id: ids.feature('ip'), text: reading.ip.slice(0, 200) },
    {
      device_feature_external_id: ids.feature('ports'),
      text: portsText(reading, 200) || t('noPorts', language),
    },
  ];
}

export {
  TARGET_TYPE,
  PUBLIC_ID,
  FEATURE_KEYS,
  MAX_PORTS,
  MAX_VULNS,
  platformId,
  targetIds,
  targetOfExternalId,
  defaultName,
  featuresOf,
  buildTargetDevice,
  buildTargetStates,
};
