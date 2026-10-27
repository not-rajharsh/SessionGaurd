'use strict';
// demo: `npm run demo`. Starts engine + app + the netsim edge proxy, registers the demo passkey if
// needed, runs the three attack scenarios, tears everything down. Needs Redis (REDIS_URL).
// Exit code mirrors attack.js (0 = all three scenarios behaved as designed).
const path = require('node:path');
const { spawn } = require('node:child_process');
const { ensureEnv, ROOT } = require('./ensure-env');
const { startEngine, waitFor } = require('./engine');
const { startNetsim } = require('./netsim');
const { registerPasskey } = require('./register-passkey');

async function main() {
  ensureEnv();
  const { createClient } = require('redis');
  const probe = createClient({ url: process.env.REDIS_URL, socket: { reconnectStrategy: false } });
  probe.on('error', () => {});
  try {
    await probe.connect(); await probe.ping(); await probe.quit();
  } catch {
    throw new Error(`Redis not reachable at ${process.env.REDIS_URL}. Start it with "redis-server" or "docker run -p 6379:6379 redis:7".`);
  }
  const enginePort = process.env.ENGINE_PORT || 8000;
  const appPort = process.env.APP_PORT || 3000;
  const netsimPort = process.env.NETSIM_PORT || 3001;
  const origins = `http://localhost:${appPort},http://localhost:${netsimPort}`;
  const children = [];
  let proxy;
  const cleanup = () => { children.forEach((c) => c.kill()); if (proxy) proxy.close(); };
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    console.log('==== session-guard Phase 2 demo ====');
    children.push(startEngine({ port: enginePort }));
    await waitFor(`http://127.0.0.1:${enginePort}/health`);
    // The app trusts X-Forwarded-For ONLY from loopback, i.e. from the netsim edge proxy below.
    children.push(spawn(process.execPath, [path.join(ROOT, 'demo-app', 'server.js')], {
      stdio: 'inherit', env: { ...process.env, TRUST_PROXY: 'loopback', WEBAUTHN_ORIGINS: origins },
    }));
    await waitFor(`http://127.0.0.1:${appPort}/health`);
    proxy = await startNetsim({ port: Number(netsimPort), targetPort: Number(appPort) });
    console.log(`[demo] engine :${enginePort}, app :${appPort}, edge simulator :${netsimPort} up`);

    const reg = await registerPasskey({ baseUrl: `http://localhost:${appPort}`, user: process.env.DEMO_USER, password: process.env.DEMO_PASSWORD });
    console.log(reg.skipped ? '[demo] passkey already registered' : '[demo] registered a passkey for the demo user (virtual authenticator)');

    return await new Promise((resolve) => {
      spawn(process.execPath, [path.join(ROOT, 'attack', 'attack.js')], { stdio: 'inherit' }).on('exit', (c) => resolve(c ?? 1));
    });
  } finally { cleanup(); }
}

main().then((c) => process.exit(c)).catch((e) => { console.error(`\n[demo] ${e.message}`); process.exit(1); });
