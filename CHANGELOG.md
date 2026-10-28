# Changelog

All notable changes to this integration are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/). This file is generated at
each release from the Conventional Commits: do not edit it by hand.

## [0.1.0] - 2026-10-28

### Added

- **exposure:** what Shodan knows of the public address of the home (checked every 15 minutes, following a change of address) and of up to 10 public addresses or host names, through Shodan InternetDB without a key, or through the Shodan API with an optional key (software and version of each service, CVSS scores, date of the last scan); read only, nothing is scanned from Gladys
- **devices:** one device per address: open ports, vulnerabilities, IP address and exposed ports
- **scenes:** triggers on a port opened or closed, a vulnerability found or gone, a Shodan tag added, a change of the public address and a refused API key; actions to read the values of an address, look up any address, and ask Shodan for a scan (paid plans)
- **widgets:** the exposure of every address, the worst first; one address with its services, CVE, tags, a button to read it again and a link to shodan.io; the plan and credits of the API key
- **configuration:** public address, other addresses, optional API key, language, "Test the connection" and "Diagnostic" buttons
- **i18n:** English, French, German and Spanish for the manifest, the runtime texts, the documentation and the README

[0.1.0]: https://github.com/William-De71/gladys-shodan/releases/tag/v0.1.0
