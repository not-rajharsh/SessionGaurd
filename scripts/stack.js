'use strict';
// stack: spins up a real engine (child process, in-memory state) + real app (in-process, memory
// session stores) on free ports for tests. No Redis needed. Knobs: engineEnv / appEnv.
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const session = require('express-session');
const { createApp } = require('../demo-app/server');
const { startEngine, waitFor } = require('./engine');

const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => r(p)); }); });

async function startStack({ engineEnv = {}, appEnv = {} } = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-'));
  const enginePort = await freePort();
  const appPort = await freePort();
  const env = {
    SESSION_SECRET: 's3cret-for-tests', ENGINE_API_KEY: 'stack-key', DEMO_USER: 'demo', DEMO_PASSWORD: 'pw-for-tests',
    ADMIN_USER: 'admin', ADMIN_PASSWORD: 'admin-pw-for-tests', RISK_ENGINE_URL: `http://127.0.0.1:${enginePort}`,
    EXPOSE_SIGNALS: 'true', APP_PORT: String(appPort), WEBAUTHN_ORIGINS: `http://localhost:${appPort}`,
    PASSKEY_STORE_PATH: path.join(tmp, 'passkeys.json'), ENGINE_TIMEOUT_MS: '10000', ...appEnv,
  };
  const engine = startEngine({ port: enginePort, stdio: 'ignore',
    env: { ENGINE_API_KEY: env.ENGINE_API_KEY, RISK_STATE: 'memory', SQLITE_PATH: path.join(tmp, 'e.db'), ...engineEnv } });
  await waitFor(`${env.RISK_ENGINE_URL}/health`);
  const app = createApp({ store: new session.MemoryStore(), adminStore: new session.MemoryStore(), env });
  const server = await new Promise((r) => { const s = app.listen(appPort, '127.0.0.1', () => r(s)); });
  return {
    env, tmp, base: `http://localhost:${appPort}`, direct: `http://127.0.0.1:${appPort}`,
    stop: () => { server.close(); engine.kill(); fs.rmSync(tmp, { recursive: true, force: true }); },
  };
}

module.exports = { startStack, freePort };
