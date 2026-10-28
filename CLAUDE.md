# CLAUDE.md

Project rules for coding assistants (Claude Code reads this file) and for human
contributors.

## What this is

A Gladys Assistant **external integration** for **Shodan**: what the Internet
sees of the home. A Node.js service (Node 22+, ESM, no build step) in its own
sandboxed Docker container, talking to Gladys through
[`@gladysassistant/integration-sdk`](https://github.com/GladysAssistant/integration-sdk-js),
its only runtime dependency, and to two official Shodan services:

- **InternetDB** (<https://internetdb.shodan.io>), no key, free for
  non-commercial use, refreshed once a week: ports, CVE, host names, tags, CPE;
- the **Shodan API** (<https://developer.shodan.io/api>, base
  `https://api.shodan.io`, `?key=`), with the optional key of the user's own
  account: services (product, version), CVSS, last scan, credits, scans.

**Read only, never scans anything itself**: it asks Shodan what Shodan knows.
`type: "device"`, Gladys 5.3.0+, `transports: ["cloud"]`. Not affiliated with
Shodan. **Never tested with a real API key**: the shapes come from the
documentation and from the live answers below.

Checked live on 2026-10-28: a wrong key gets **401 and an HTML page** on every
endpoint but `/tools/myip`, which answers with any key or none (used without a
key when none is set: undocumented); `/shodan/host/{private ip}` answers 404
`{"error":"Invalid IP"}`; InternetDB answers 404
`{"detail":"No information available"}` for an address it does not know, and
its CDN keeps an answer up to 5 days (`max-age=432000`).

## Commands

```bash
npm install
npm test                                  # node --test; a fake Shodan (in-memory fetch, fake clock)
node --test test/app.test.js              # one file
UPDATE_BASELINE=1 npm test                # rewrite test/fixtures/discovery.baseline.json (on purpose only)
npm run lint                              # ESLint
npm run format:check                      # Prettier, as the CI runs it
npx github:GladysAssistant/integration-store . --skip-image-check   # store checks
scripts/build-cover.sh                    # cover.jpg from docs/assets/cover.svg
docs/illustrations/render.sh              # docs/assets/widgets.<lang>.png
node .github/scripts/release.mjs next     # the version the next release would get
```

## Architecture

```
index.js                 SDK wiring only (new GladysIntegration + createApp)
src/app.js               every handler; the timer (what is due), the targets (public address,
                         typed addresses), the choice API / InternetDB, devices and states,
                         scene events, scene actions, widgets, configuration buttons, status
src/shodan-api.js        HTTP client of both services: one request at a time 1.1 s apart, a pause
                         per service after 429 / 5xx / no answer, the key never in an error
src/parse.js             the answers made safe (one reading shape for both sources), public
                         addresses, the addresses typed
src/device.js            one device per address, features and states
src/events.js            triggers (ports, CVE, tags), outputs, summaries
src/widgets.js           overview, one address, account
src/time.js              local times (Intl only)
src/store.js             /data/shodan.json (mode 0600; never the key)
src/config.js            public address, addresses, key, language
src/i18n.js              helpers (t, tn for plurals); src/i18n-texts.js the runtime texts
test/helpers/fake-shodan.js   the fake Shodan (InternetDB, API, refusals, scans)
test/fixtures/hosts.json      made-up answers on documentation addresses (RFC 5737)
.github/scripts/release.mjs   version, changelog, bump (tested in test/)
```

## Rules

- **External ids are forever**, and so is every key users store:
  `ext:<selector>:target:public` for the public address (one device whatever
  the address), `ext:<selector>:target:<address>` for a typed one (every
  character outside `[A-Za-z0-9_-]` replaced by `-`), features `…:<key>`
  (`open_ports`, `vulnerabilities`, `ip`, `ports`); feature `category` /
  `type` / `unit` / `min` / `max`, the keys of `config_schema` and `actions`,
  `last_language`, widgets and settings, the widget button `refresh`, triggers
  (fields, options, variables), scene actions (fields, outputs).
  `test/structure.test.js` compares them to
  `test/fixtures/discovery.baseline.json`: never update it to make a test pass
  without a documented migration.
- **Category pairs**: counter-sensor / integer (no unit) for the counts, text /
  text for the address and the ports. No CVSS feature: the core has no decimal
  counter; the CVSS lives in widgets, variables and outputs.
- **The pace.** A 1-minute timer: the public address every 15 minutes, each
  address every 6 hours or at once when its IP changed, a retry 30 minutes
  after a failure, the credits every 6 hours, a scan every 2 minutes until done
  (given up after 2 hours). Shodan asks one request a second at most.
- **Sources.** With a key Shodan accepts: the API host lookup. A 401 falls back
  to InternetDB, fires `access_refused` once and tries the key again every
  6 hours; a 403 (plan) falls back to InternetDB for 24 hours without any
  trigger. A 404 is a reading without ports (`found: false`), never an error.
- **Baselines.** Scene events once per transition, never at the first reading,
  never from a scene action (the detection runs on the timer only, after the
  readings). A new address or a new source starts a new baseline silently:
  what Shodan knows of a freshly assigned address may describe its previous
  holder. At most 10 events of a kind per address and per reading.
- **Addresses.** Public ones only (`isPublicIp`): private, loopback, CGNAT,
  link-local and reserved ranges are refused (`parse.js`); `.local` / `.lan`
  names are refused; host names are resolved by the DNS of the container at
  each reading, IPv4 first.
- **`should_poll` stays false**: the integration has its own timer.
- **The key** is a `secret`, never logged, never in /data, never in an error
  message (`fetch` errors may carry the URL: only their name is kept), sent to
  api.shodan.io only, never to InternetDB. Test keys never look real
  (`not-a-real-shodan-key`): the push protection of GitHub would block them.
- **The container rootfs is read-only.** Write only under `/data`.
- **Four languages.** Every user-facing text (manifest, `src/i18n-texts.js`,
  `docs/*.md`, README) exists in en, fr, de, es; `test/i18n.test.js` checks it.
  German says "du", Spanish "usted". Plurals: `<key>_one` / `<key>_other`.
- **Widget images.** After any change to a widget content, run
  `docs/illustrations/render.sh` again and look at the four PNG files (tile
  labels are cut beyond about 14 characters when three tiles share a row).
- **Versions belong to the Release workflow**: never edit `version` in
  `package.json`, the lockfile or the manifest, nor the `docker_image` tag.
  Below 1.0.0 until the maintainer runs Release with `release-as: 1.0.0`.
- **Changelog.** Ne jamais éditer CHANGELOG.md à la main, il est généré à la
  release. Écris le titre de PR comme la ligne que l'utilisateur lira.
- **Commits and PR titles** follow Conventional Commits, in English.
- **Forum drafts** (`.github/forum-*.md`) are never committed.
- **Style.** Prettier formats, ESLint catches mistakes. Comments explain why,
  in English. Tests never touch the network.

## Pitfalls

- InternetDB is refreshed weekly and cached 5 days: most readings bring
  nothing new, which is expected.
- `vulns` are CVE matched to versions by Shodan, not verified on the machine:
  say so in every text that shows them.
- The Shodan free plan may refuse host lookups and has no scan credits: the
  fallback to InternetDB covers the first, the scan action says the second.
- `node --test` also runs `test/helpers/`: nothing starts on import.
- The validator of the Gladys core creates `gladys-development.duckdb` in the
  current folder: run it from elsewhere.
