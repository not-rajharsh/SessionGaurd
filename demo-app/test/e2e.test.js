'use strict';
// End-to-end (no browser): real Express app + real FastAPI engine (in-memory state).
// Proves: a legitimate session is allowed; the same cookie replayed from another
// UA / network is blocked and the session is killed.
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const session = require('express-session');
const { createApp } = require('../server');
const { startEngine, waitFor } = require('../../scripts/engine');

const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => r(p)); }); });

const LEGIT = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130 Legit', 'x-forwarded-for': '203.0.113.10', 'accept-language': 'en-US' };
const ATTACKER = { ...LEGIT, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Firefox/120 Attacker', 'x-forwarded-for': '198.51.100.20' };

let engine, appSrv, base, tmp;

test.before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-'));
  const enginePort = await freePort();
  const env = {
    SESSION_SECRET: 's3cret-for-tests', ENGINE_API_KEY: 'e2e-key', DEMO_USER: 'demo', DEMO_PASSWORD: 'pw-for-tests',
    RISK_ENGINE_URL: `http://127.0.0.1:${enginePort}`, TRUST_PROXY: 'true', EXPOSE_SIGNALS: 'true', REQUIRE_DEVICE_KEY: 'false',
  };
  engine = startEngine({ port: enginePort, stdio: 'ignore', env: { ENGINE_API_KEY: env.ENGINE_API_KEY, RISK_STATE: 'memory', SQLITE_PATH: path.join(tmp, 'e.db') } });
  await waitFor(`${env.RISK_ENGINE_URL}/health`);
  const app = createApp({ store: new session.MemoryStore(), env });
  appSrv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  base = `http://127.0.0.1:${appSrv.address().port}`;
  process.env.__DEMO_PW = env.DEMO_PASSWORD;
});

test.after(() => { appSrv?.close(); engine?.kill(); fs.rmSync(tmp, { recursive: true, force: true }); });

async function login(headers) {
  const r = await fetch(`${base}/login`, {
    method: 'POST', redirect: 'manual',
    headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'demo', password: process.env.__DEMO_PW }),
  });
  assert.equal(r.status, 302);
  return r.headers.getSetCookie()[0].split(';')[0];
}

test('wrong password is rejected', async () => {
  const r = await fetch(`${base}/login`, { method: 'POST', headers: { ...LEGIT, 'content-type': 'application/x-www-form-urlencoded' }, body: 'username=demo&password=nope' });
  assert.equal(r.status, 401);
});

test('state-changing requests without a session get 401, not a redirect', async () => {
  const r = await fetch(`${base}/transfer`, { method: 'POST', redirect: 'manual', headers: { ...LEGIT, 'content-type': 'application/json' }, body: JSON.stringify({ to: 'x', amount: 1 }) });
  assert.equal(r.status, 401);
});

test('legitimate session is allowed; replayed session is blocked', async () => {
  const cookie = await login(LEGIT);

  const me = await fetch(`${base}/api/me`, { headers: { ...LEGIT, cookie } });
  assert.equal(me.status, 200);
  assert.equal((await me.json()).risk.action, 'allow');

  const tx = await fetch(`${base}/transfer`, { method: 'POST', headers: { ...LEGIT, cookie, 'content-type': 'application/json' }, body: JSON.stringify({ to: 'alice', amount: 100 }) });
  assert.equal(tx.status, 200);

  // Replay the stolen cookie from a different UA and network.
  const stolen = await fetch(`${base}/transfer`, { method: 'POST', headers: { ...ATTACKER, cookie, 'content-type': 'application/json' }, body: JSON.stringify({ to: 'mallory', amount: 5000 }) });
  const j = await stolen.json();
  assert.equal(stolen.status, 401);
  assert.equal(j.error, 'session_terminated');
  const names = j.signals.map((s) => s.name);
  for (const n of ['user_agent_mismatch', 'asn_change', 'impossible_travel']) assert.ok(names.includes(n), `missing ${n}`);

  // The session is dead for everyone, including the original browser.
  const after = await fetch(`${base}/api/me`, { headers: { ...LEGIT, cookie, accept: 'application/json' } });
  assert.equal(after.status, 401);
});
