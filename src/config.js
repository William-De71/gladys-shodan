// -----------------------------------------------------------------------------
// Configuration of the Shodan integration.
//
// Fields of the config_schema:
//   - `monitor_public_ip` watch the public address of the home (true by
//                         default): the address the requests leave from,
//                         asked to Shodan every 15 minutes;
//   - `addresses`         other public addresses or host names (a dynamic DNS
//                         name, a server), 10 at most;
//   - `api_key`           the key of a Shodan account, optional: a `secret`,
//                         never sent back to the UI, never logged, never
//                         written to /data, only sent to api.shodan.io. With
//                         it: the services (product, version), the CVSS
//                         scores, the date of the last scan, the credits and
//                         the on-demand scan;
//   - `language`          language of the texts Gladys does not ask for in a
//                         language (feature names, scene texts): `auto`
//                         follows the language of the last widget, or the
//                         timezone.
//
// Internal key, outside the config_schema (never shown in the UI):
//   - `last_language` language of the last widget request.
// -----------------------------------------------------------------------------

import { isLanguage } from './i18n.js';
import { parseAddresses } from './parse.js';

const AUTO_LANGUAGE = 'auto';
const INTERNAL_KEYS = { language: 'last_language' };

const readString = (raw) =>
  typeof raw === 'string' ? raw.trim() : typeof raw === 'number' ? String(raw) : '';

const readBoolean = (raw, fallback) => {
  if (typeof raw === 'boolean') return raw;
  if (raw === 'true' || raw === 1 || raw === '1') return true;
  if (raw === 'false' || raw === 0 || raw === '0') return false;
  return fallback;
};

/**
 * @description Normalize the raw config object from the host API.
 * @param {object} [rawConfig] - The raw config values.
 * @returns {object} `{ monitorPublicIp, addresses, rejected, apiKey, language }`.
 * @example
 * normalizeConfig({ addresses: 'home.example.org, 192.168.1.1' });
 * // addresses [{ address: 'home.example.org', kind: 'host' }], rejected ['192.168.1.1']
 */
function normalizeConfig(rawConfig = {}) {
  const config = rawConfig ?? {};
  const { addresses, rejected } = parseAddresses(readString(config.addresses).slice(0, 2000));
  return {
    monitorPublicIp: readBoolean(config.monitor_public_ip, true),
    addresses,
    rejected,
    apiKey: readString(config.api_key).replace(/\s+/g, '').slice(0, 128),
    language: isLanguage(config.language) ? config.language : AUTO_LANGUAGE,
  };
}

// The timezones of the countries that speak the languages of the integration:
// the automatic language before any widget was shown.
const TIMEZONE_LANGUAGES = {
  fr: [
    'Europe/Paris',
    'Europe/Monaco',
    'Europe/Brussels',
    'Europe/Luxembourg',
    'Indian/Reunion',
    'Indian/Mayotte',
    'America/Guadeloupe',
    'America/Martinique',
    'America/Cayenne',
    'America/Miquelon',
    'Pacific/Noumea',
    'Pacific/Tahiti',
    'America/Montreal',
    'Africa/Abidjan',
    'Africa/Dakar',
    'Africa/Casablanca',
    'Africa/Algiers',
    'Africa/Tunis',
  ],
  de: ['Europe/Berlin', 'Europe/Busingen', 'Europe/Vienna', 'Europe/Zurich', 'Europe/Vaduz'],
  es: [
    'Europe/Madrid',
    'Atlantic/Canary',
    'Africa/Ceuta',
    'America/Mexico_City',
    'America/Bogota',
    'America/Lima',
    'America/Santiago',
    'America/Caracas',
    'America/Montevideo',
    'America/Asuncion',
    'America/La_Paz',
    'America/Guayaquil',
    'America/Havana',
    'America/Costa_Rica',
    'America/Panama',
  ],
};

/**
 * @description The language of the texts guessed from a timezone, before
 * any widget was shown.
 * @param {string} timezone - IANA timezone of Gladys.
 * @returns {string} en, fr, de or es.
 * @example
 * guessLanguage('Europe/Paris'); // -> 'fr'
 */
function guessLanguage(timezone) {
  const zone = String(timezone ?? '');
  if (zone.startsWith('America/Argentina/')) {
    return 'es';
  }
  const found = Object.entries(TIMEZONE_LANGUAGES).find(([, zones]) => zones.includes(zone));
  return found ? found[0] : 'en';
}

/**
 * @description Read the stored language of the last widget request.
 * @param {object} [rawConfig] - The raw config values.
 * @param {string} fallback - The language to keep when nothing valid is stored.
 * @returns {string} The language.
 */
function readLanguage(rawConfig, fallback) {
  const language = (rawConfig ?? {})[INTERNAL_KEYS.language];
  return isLanguage(language) ? language : fallback;
}

export { AUTO_LANGUAGE, INTERNAL_KEYS, normalizeConfig, guessLanguage, readLanguage };
