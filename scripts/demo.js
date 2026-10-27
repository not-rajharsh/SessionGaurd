'use strict';
// demo: `npm run demo`. Starts the risk engine and the demo app, runs attack.js, tears down.
// Needs Redis running (REDIS_URL). Exit code mirrors attack.js (0 = legit allowed AND replay blocked).
const path = require('node:path');
const { spawn } = require('node:child_process');
const { ensureEnv, ROOT } = require('./ensure-env');
const { startEngine, waitFor } = require('./engine');

async function main() {
  ensureEnv();
  const { createClient } = require('redis');
  const probe = createClient({ url: process.env.REDIS_URL, socket: { reconnectStrategy: false } });
  probe.on('error', () => {});
  try {
    await probe.connect();
    await probe.ping();
    await probe.quit();
  } catch {
    throw new Error(`Redis not reachable at ${process.env.REDIS_URL}. Start it with "redis-server" or "docker run -p 6379:6379 redis:7".`);
  }

  const enginePort = process.env.ENGINE_PORT || 8000;
  const appPort = process.env.APP_PORT || 3000;
  const children = [];
  const cleanup = () => children.forEach((c) => c.kill());
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    console.log('==== session-guard Phase 1 demo ====');
    children.push(startEngine({ port: enginePort }));
    await waitFor(`http://127.0.0.1:${enginePort}/health`);
    children.push(spawn(process.execPath, [path.join(ROOT, 'demo-app', 'server.js')], { stdio: 'inherit' }));
    await waitFor(`http://127.0.0.1:${appPort}/health`);
    console.log(`[demo] engine :${enginePort}, app :${appPort} up\n`);

    const code = await new Promise((resolve) => {
      spawn(process.execPath, [path.join(ROOT, 'attack', 'attack.js')], { stdio: 'inherit' }).on('exit', resolve);
    });
    return code ?? 1;
  } finally {
    cleanup();
  }
}

main().then((c) => process.exit(c)).catch((e) => { console.error(`\n[demo] ${e.message}`); process.exit(1); });
