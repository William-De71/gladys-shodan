// -----------------------------------------------------------------------------
// Dashboard widgets of the Shodan integration.
//
//   - `overview`  every watched address at a glance: the open ports and the
//                 vulnerabilities in all, then one card per address (the
//                 worst first) with its ports, its CVE and its tags;
//   - `target`    one address (a Shodan device, the public address by
//                 default): ports, vulnerabilities, highest CVSS, one card
//                 per service (product and version with a key), the CVE,
//                 the host names and tags, a button to read it again and a
//                 link to its page on shodan.io;
//   - `account`   the plan and the credits of the API key.
// Every text exists in the four languages (the content is cached per
// language). Content budget of a card: 8 components, 1 main one, 6 tiles,
// 2 texts (1 body), 1 status, 4 buttons.
// -----------------------------------------------------------------------------

import { WIDGET_COLORS } from '@gladysassistant/integration-sdk';
import { t, tn, ago, formatNumber } from './i18n.js';
import { formatTime } from './time.js';
import { maxCvss, portsText } from './parse.js';

const WIDGETS = { OVERVIEW: 'overview', TARGET: 'target', ACCOUNT: 'account' };
const WIDGET_ACTIONS = { REFRESH: 'refresh' };
const TTL_SECONDS = { overview: 600, target: 600, account: 900, message: 120 };
const MAX_CARDS = 8;
// Tags that mean more than an exposure.
const ALARM_TAGS = ['compromised', 'malware', 'doublepulsar'];

/**
 * @description Truncate a text to a bound, with an ellipsis.
 * @param {string} value - The text.
 * @param {number} max - The bound.
 * @returns {string} The text.
 */
function clip(value, max) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * @description A widget content made of one message.
 * @param {string} message - The message.
 * @param {object} [options] - `{ heading, ttl }`.
 * @returns {object} The content.
 */
function messageContent(message, { heading, ttl = TTL_SECONDS.message } = {}) {
  const components = [];
  if (heading) {
    components.push({ type: 'text', variant: 'heading', text: clip(heading, 40) });
  }
  components.push({ type: 'text', variant: 'body', text: clip(message, 300) });
  return { ttl_seconds: ttl, components };
}

/**
 * @description The page of an address on shodan.io.
 * @param {string} ip - The address.
 * @returns {string} The URL.
 */
const hostUrl = (ip) => `https://www.shodan.io/host/${encodeURIComponent(ip)}`;

/**
 * @description The colon of a language: French puts a space before it.
 * @param {string} language - The language.
 * @returns {string} " : " or ": ".
 */
const colon = (language) => (language === 'fr' ? ' : ' : ': ');

/**
 * @description The color of a CVSS score.
 * @param {number|null} score - The score.
 * @returns {string} A semantic color.
 */
function cvssColor(score) {
  if (!Number.isFinite(score)) return WIDGET_COLORS.WARNING;
  if (score >= 7) return WIDGET_COLORS.DANGER;
  if (score >= 4) return WIDGET_COLORS.WARNING;
  return WIDGET_COLORS.INFO;
}

/**
 * @description How worrying an address is, for the order of the cards.
 * @param {object} view - The view of the target (app.js).
 * @returns {number} 4 alarm tag, 3 vulnerabilities, 2 error, 1 open ports, 0 nothing.
 */
function urgency(view) {
  const reading = view.reading;
  if (reading?.tags.some((tag) => ALARM_TAGS.includes(tag))) return 4;
  if (reading?.vulns.length) return 3;
  if (view.error || !reading) return 2;
  if (reading.ports.length) return 1;
  return 0;
}

/**
 * @description The badge of an address.
 * @param {object} view - The view of the target.
 * @param {string} language - The language.
 * @returns {{ text: string, color: string }} The badge.
 */
function badgeOf(view, language) {
  const reading = view.reading;
  if (!reading) {
    return view.error
      ? { text: t('badgeError', language), color: WIDGET_COLORS.WARNING }
      : { text: t('badgeWaiting', language), color: WIDGET_COLORS.NEUTRAL };
  }
  const alarm = reading.tags.find((tag) => ALARM_TAGS.includes(tag));
  if (alarm) return { text: alarm, color: WIDGET_COLORS.DANGER };
  if (reading.vulns.length) {
    return {
      text: tn('badgeVulns', reading.vulns.length, language),
      color: cvssColor(maxCvss(reading)),
    };
  }
  if (reading.ports.length) {
    return {
      text: tn('badgePorts', reading.ports.length, language),
      color: WIDGET_COLORS.INFO,
    };
  }
  return { text: t('badgeNothing', language), color: WIDGET_COLORS.SUCCESS };
}

/**
 * @description The card of an address.
 * @param {object} view - The view of the target.
 * @param {object} options - `{ language, now }`.
 * @returns {object} A card-list item.
 */
function targetCard(view, { language, now }) {
  const { reading } = view;
  const parts = reading
    ? [
        reading.ip,
        tn('portsShort', reading.ports.length, language),
        tn('vulnsShort', reading.vulns.length, language),
        ago(view.readAt, now, language),
      ]
    : [view.ip ?? '', view.error ? view.error : t('statusWaiting', language)];
  const badge = badgeOf(view, language);
  const card = {
    title: clip(view.name, 60),
    subtitle: clip(parts.filter(Boolean).join(' · '), 60),
    badge: { text: clip(badge.text, 16), color: badge.color },
  };
  if (reading) {
    const lines = [
      `${t('rowPorts', language)}${colon(language)}${portsText(reading, 600) || t('noPorts', language)}`,
      ...(reading.vulns.length
        ? [`${t('rowVulns', language)}${colon(language)}${cveText(reading, 30, 1200)}`]
        : []),
      ...(reading.tags.length
        ? [`${t('rowTags', language)}${colon(language)}${reading.tags.join(', ')}`]
        : []),
    ];
    card.description = clip(lines.join('\n'), 2000);
    card.links = [{ url: hostUrl(reading.ip), label: t('linkShodan', language) }];
  }
  return card;
}

/**
 * @description The CVE of a reading, the highest scores first: "CVE-2023-38408 (9.8), …".
 * @param {object} reading - The reading.
 * @param {number} count - How many at most.
 * @param {number} max - Characters at most.
 * @returns {string} The text.
 */
function cveText(reading, count, max) {
  const sorted = [...reading.vulns].sort(
    (a, b) => (reading.cvss[b] ?? -1) - (reading.cvss[a] ?? -1) || b.localeCompare(a),
  );
  const list = sorted
    .slice(0, count)
    .map((id) => (Number.isFinite(reading.cvss[id]) ? `${id} (${reading.cvss[id]})` : id));
  const more = reading.vulns.length - Math.min(count, reading.vulns.length);
  return clip(`${list.join(', ')}${more > 0 ? ` +${more}` : ''}`, max);
}

/**
 * @description The "overview" widget.
 * @param {object} options - Options.
 * @param {object[]} options.views - The views of the targets (app.js).
 * @param {string} options.language - The user language.
 * @param {number} options.now - Now (ms).
 * @param {boolean} options.hasKey - Whether an API key is set.
 * @returns {object} The content.
 */
function buildOverviewWidget({ views, language, now, hasKey }) {
  const read = views.filter((view) => view.reading);
  const ports = read.reduce((sum, view) => sum + view.reading.ports.length, 0);
  const vulns = read.reduce((sum, view) => sum + view.reading.vulns.length, 0);
  const components = [
    {
      type: 'value',
      label: clip(t('tilePorts', language), 24),
      value: ports,
      icon: 'unlock',
      color: ports ? WIDGET_COLORS.INFO : WIDGET_COLORS.SUCCESS,
    },
    {
      type: 'value',
      label: clip(t('tileVulns', language), 24),
      value: vulns,
      icon: 'alert-triangle',
      color: vulns ? WIDGET_COLORS.DANGER : WIDGET_COLORS.SUCCESS,
    },
  ];
  const sorted = [...views].sort(
    (a, b) => urgency(b) - urgency(a) || a.name.localeCompare(b.name, language),
  );
  if (sorted.length) {
    components.push({
      type: 'card-list',
      display: 'list',
      items: sorted.slice(0, MAX_CARDS).map((view) => targetCard(view, { language, now })),
    });
  }
  components.push({
    type: 'text',
    variant: 'caption',
    text: clip(t(hasKey ? 'captionApi' : 'captionInternetDb', language), 80),
  });
  return { ttl_seconds: TTL_SECONDS.overview, components };
}

/**
 * @description The card of a port (a service with the API, a bare port with InternetDB).
 * @param {object} reading - The reading.
 * @param {number} port - The port.
 * @param {string} language - The language.
 * @returns {object} A card-list item.
 */
function portCard(reading, port, language) {
  const service = reading.services.find((item) => item.port === port);
  const vulns = service?.vulns ?? [];
  const card = {
    title: service ? `${port}/${service.transport}` : String(port),
    subtitle: clip(
      service
        ? [service.product, service.version].filter(Boolean).join(' ') ||
            t('unknownService', language)
        : t('openPort', language),
      60,
    ),
  };
  if (vulns.length) {
    card.badge = {
      text: clip(tn('badgeVulns', vulns.length, language), 16),
      color: cvssColor(Math.max(...vulns.map((id) => reading.cvss[id] ?? -1))),
    };
    card.description = clip(
      vulns
        .map((id) =>
          [
            Number.isFinite(reading.cvss[id]) ? `${id} (CVSS ${reading.cvss[id]})` : id,
            reading.summaries[id],
          ]
            .filter(Boolean)
            .join(colon(language)),
        )
        .join('\n\n'),
      2000,
    );
  }
  return card;
}

/**
 * @description The "target" widget.
 * @param {object} options - Options.
 * @param {object} options.view - The view of the target (app.js).
 * @param {string} options.language - The user language.
 * @param {number} options.now - Now (ms).
 * @param {string} options.timeZone - The timezone of Gladys.
 * @returns {object} The content.
 */
function buildTargetWidget({ view, language, now, timeZone }) {
  const { reading } = view;
  if (!reading) {
    return messageContent(view.error ?? t('statusWaiting', language), { heading: view.name });
  }
  const top = maxCvss(reading);
  const components = [
    { type: 'text', variant: 'heading', text: clip(view.name, 40) },
    {
      type: 'value',
      label: clip(t('tilePorts', language), 24),
      value: reading.ports.length,
      icon: 'unlock',
      color: reading.ports.length ? WIDGET_COLORS.INFO : WIDGET_COLORS.SUCCESS,
    },
    {
      type: 'value',
      label: clip(t('tileVulns', language), 24),
      value: reading.vulns.length,
      icon: 'alert-triangle',
      color: reading.vulns.length ? cvssColor(top) : WIDGET_COLORS.SUCCESS,
    },
  ];
  if (Number.isFinite(top)) {
    components.push({
      type: 'value',
      label: clip(t('tileCvss', language), 24),
      value: formatNumber(top, language, 1),
      icon: 'activity',
      color: cvssColor(top),
    });
  }
  if (reading.ports.length) {
    components.push({
      type: 'card-list',
      display: 'list',
      items: reading.ports.slice(0, 8).map((port) => portCard(reading, port, language)),
    });
  }
  components.push({
    type: 'text',
    variant: 'body',
    text: clip(
      reading.vulns.length
        ? t('bodyVulns', language, { list: cveText(reading, 12, 260) })
        : reading.ports.length
          ? t('bodyNoVulns', language)
          : t('bodyNothing', language),
      300,
    ),
  });
  const rows = [
    {
      label: clip(t('rowIp', language), 40),
      value: clip(reading.ip, 40),
      color: WIDGET_COLORS.NEUTRAL,
    },
  ];
  if (Number.isFinite(reading.lastUpdate)) {
    rows.push({
      label: clip(t('rowLastScan', language), 40),
      value: clip(
        t('rowAgo', language, {
          time: formatTime(reading.lastUpdate, { language, timeZone, now }),
          ago: ago(reading.lastUpdate, now, language),
        }),
        40,
      ),
      color: WIDGET_COLORS.NEUTRAL,
    });
  }
  rows.push({
    label: clip(t('rowRead', language), 40),
    value: clip(ago(view.readAt, now, language), 40),
    color: view.error ? WIDGET_COLORS.WARNING : WIDGET_COLORS.SUCCESS,
  });
  if (reading.hostnames.length) {
    rows.push({
      label: clip(t('rowHostnames', language), 40),
      value: clip(reading.hostnames.join(', '), 40),
      color: WIDGET_COLORS.NEUTRAL,
    });
  }
  if (reading.tags.length) {
    rows.push({
      label: clip(t('rowTags', language), 40),
      value: clip(reading.tags.join(', '), 40),
      color: reading.tags.some((tag) => ALARM_TAGS.includes(tag))
        ? WIDGET_COLORS.DANGER
        : WIDGET_COLORS.INFO,
    });
  }
  const owner = [reading.org, reading.isp].filter(Boolean);
  if (owner.length) {
    rows.push({
      label: clip(t('rowOrg', language), 40),
      value: clip([...new Set(owner)].join(' · '), 40),
      color: WIDGET_COLORS.NEUTRAL,
    });
  }
  rows.push({
    label: clip(t('rowSource', language), 40),
    value: clip(t(reading.source === 'api' ? 'sourceApi' : 'sourceInternetDb', language), 40),
    color: WIDGET_COLORS.NEUTRAL,
  });
  components.push({ type: 'status', items: rows.slice(0, 10) });
  components.push({
    type: 'button',
    label: clip(t('buttonRefresh', language), 24),
    icon: 'refresh-cw',
    style: 'secondary',
    action: { key: WIDGET_ACTIONS.REFRESH, params: { target: view.platformId } },
  });
  components.push({
    type: 'button',
    label: clip(t('linkShodan', language), 24),
    icon: 'external-link',
    style: 'secondary',
    link: { url: hostUrl(reading.ip) },
  });
  return { ttl_seconds: TTL_SECONDS.target, components };
}

/**
 * @description A count against its limit: "87 / 100".
 * @param {number|null} value - The count.
 * @param {number|null} limit - The limit.
 * @param {string} language - The language.
 * @returns {string|number} The value of a tile.
 */
function ofLimit(value, limit, language) {
  if (!Number.isFinite(value)) return '–';
  const text = formatNumber(value, language, 0);
  return Number.isFinite(limit) && limit > 0
    ? clip(`${text}/${formatNumber(limit, language, 0)}`, 12)
    : value;
}

/**
 * @description The "account" widget.
 * @param {object} options - Options.
 * @param {object} options.info - parseApiInfo().
 * @param {number} options.readAt - When it was read (ms).
 * @param {object[]} options.scans - The scans asked (`{ id, ip, status, at }`).
 * @param {string} options.language - The user language.
 * @param {number} options.now - Now (ms).
 * @returns {object} The content.
 */
function buildAccountWidget({ info, readAt, scans, language, now }) {
  const low = (value, limit) =>
    Number.isFinite(value) && Number.isFinite(limit) && limit > 0 && value <= limit * 0.1;
  const components = [
    {
      type: 'value',
      label: clip(t('tileQueryCredits', language), 24),
      value: ofLimit(info.queryCredits, info.limits.queryCredits, language),
      icon: 'search',
      color: low(info.queryCredits, info.limits.queryCredits)
        ? WIDGET_COLORS.WARNING
        : WIDGET_COLORS.PRIMARY,
    },
    {
      type: 'value',
      label: clip(t('tileScanCredits', language), 24),
      value: ofLimit(info.scanCredits, info.limits.scanCredits, language),
      icon: 'crosshair',
      color: info.scanCredits ? WIDGET_COLORS.PRIMARY : WIDGET_COLORS.NEUTRAL,
    },
  ];
  if (Number.isFinite(info.limits.monitoredIps) && info.limits.monitoredIps > 0) {
    components.push({
      type: 'value',
      label: clip(t('tileMonitored', language), 24),
      value: ofLimit(info.monitoredIps, info.limits.monitoredIps, language),
      icon: 'eye',
      color: WIDGET_COLORS.INFO,
    });
  }
  const rows = [
    {
      label: clip(t('rowPlan', language), 40),
      value: clip(info.plan ?? '–', 40),
      color: WIDGET_COLORS.NEUTRAL,
    },
    {
      label: clip(t('rowRead', language), 40),
      value: clip(ago(readAt, now, language), 40),
      color: WIDGET_COLORS.SUCCESS,
    },
  ];
  for (const scan of scans.slice(-3).reverse()) {
    rows.push({
      label: clip(t('rowScan', language, { ip: scan.ip }), 40),
      value: clip(t(`scan_${scan.status}`, language), 40),
      color:
        scan.status === 'DONE'
          ? WIDGET_COLORS.SUCCESS
          : scan.status === 'FAILED'
            ? WIDGET_COLORS.DANGER
            : WIDGET_COLORS.INFO,
    });
  }
  components.push({ type: 'status', items: rows });
  return { ttl_seconds: TTL_SECONDS.account, components };
}

export {
  WIDGETS,
  WIDGET_ACTIONS,
  TTL_SECONDS,
  MAX_CARDS,
  ALARM_TAGS,
  clip,
  messageContent,
  hostUrl,
  cvssColor,
  cveText,
  buildOverviewWidget,
  buildTargetWidget,
  buildAccountWidget,
};
