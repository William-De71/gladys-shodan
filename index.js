// -----------------------------------------------------------------------------
// Entry point of the Shodan external integration.
//
// What the Internet sees of the home, as Shodan knows it: the public address
// of the home and the addresses typed in the configuration, through Shodan
// InternetDB (no key) or the Shodan API (an optional key), read only:
//   - devices: one per address (open ports, vulnerabilities, address,
//     exposed ports), offered on the Discovery screen (src/device.js);
//   - scene triggers: port opened or closed, vulnerability found or gone,
//     Shodan tag added, public address changed, API key refused;
//   - scene actions: values of an address, look up an address, scan;
//   - dashboard widgets: overview, one address, account.
//
// This file only wires the SDK client: the handlers are in src/app.js.
//
// Environment variables provided by the Gladys supervisor:
//   GLADYS_HOST_API_URL / GLADYS_INTEGRATION_TOKEN / GLADYS_INTEGRATION_SELECTOR
//   TZ (the timezone of Gladys: the times shown by the widgets)
// The SDK reads the first three: `new GladysIntegration()` is enough.
// -----------------------------------------------------------------------------

import { readFileSync } from 'node:fs';
import { GladysIntegration, logger } from '@gladysassistant/integration-sdk';
import { createApp } from './src/app.js';

const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const gladys = new GladysIntegration();
createApp(gladys);

// --- Startup -----------------------------------------------------------------------
logger.info(`Starting the Shodan integration ${version}...`);
gladys.connect().catch((err) => {
  logger.error('Initial connection failed', err);
  process.exit(1);
});
