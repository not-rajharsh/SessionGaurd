'use strict';
// B5 end to end (no browser): real app + real engine, with Node's crypto standing in for the browser's
// WebCrypto key. The adaptive attacker has the victim's cookie, UA, headers and IP but NOT the key.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startStack } = require('../../scripts/stack');

const HEADERS = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130 Victim', 'accept-language': 'en-US', 'accept-encoding': 'gzip, br' };
let stack;
test.before(async () => { stack = await startStack(); });
test.after(() => stack.stop());

function newDevice() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    sign: (msg) => crypto.sign('sha256', Buffer.from(msg), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'), // = WebCrypto output
  };
}

async function login(device, extra = {}) {
  const body = new URLSearchParams({ username: 'demo', password: stack.env.DEMO_PASSWORD, ...(device ? { pubkey: device.spki } : {}), ...extra });
  const r = await fetch(`${stack.direct}/login`, { method: 'POST', redirect: 'manual', headers: { ...HEADERS, 'content-type': 'application/x-www-form-urlencoded' }, body });
  return { status: r.status, cookie: r.headers.getSetCookie()[0]?.split(';')[0] };
}

const call = (cookie, path, { method = 'GET', headers = {}, body } = {}) =>
  fetch(`${stack.direct}${path}`, { method, redirect: 'manual', headers: { ...HEADERS, accept: 'application/json', cookie, ...(body ? { 'content-type': 'application/json' } : {}), ...headers }, body: body && JSON.stringify(body) });

async function proof(cookie, device, purpose) {
  const { nonce } = await (await call(cookie, '/auth/challenge', { method: 'POST' })).json();
  return `${nonce}.${device.sign(`${nonce}|${purpose}`)}`;
}
const transferWith = async (cookie, device, amount = 100) =>
  call(cookie, '/transfer', { method: 'POST', body: { to: 'alice', amount }, headers: device ? { 'x-device-proof': await proof(cookie, device, 'POST /transfer') } : {} });

test('legitimate device: presence and a proven transfer are allowed', async () => {
  const device = newDevice();
  const { cookie } = await login(device);
  assert.equal((await call(cookie, '/api/me')).status, 200);
  const presence = await call(cookie, '/auth/presence', { method: 'POST', headers: { 'x-device-proof': await proof(cookie, device, 'presence') } });
  assert.equal(presence.status, 204);
  const tx = await transferWith(cookie, device);
  assert.equal(tx.status, 200);
  assert.equal((await tx.json()).ok, true);
});

test('B5 adaptive attacker (cookie + identical UA/headers/IP, no key): transfer is forced to step-up', async () => {
  const { cookie } = await login(newDevice());
  const r = await transferWith(cookie, null); // attacker replays the cookie, nothing else differs
  const j = await r.json();
  assert.equal(r.status, 403);
  assert.equal(j.error, 'step_up_required');
  assert.deepEqual(j.signals.map((s) => s.name), ['proof_missing']); // layer 1 saw nothing; layer 2 caught it
});

test('B5 attacker who signs with their own key is terminated, and the session dies', async () => {
  const { cookie } = await login(newDevice());
  const r = await transferWith(cookie, newDevice()); // challenge is fetchable with the cookie; the signature is not forgeable
  const j = await r.json();
  assert.equal(r.status, 401);
  assert.equal(j.error, 'session_terminated');
  assert.ok(j.signals.some((s) => s.name === 'proof_invalid'));
  assert.equal((await call(cookie, '/api/me')).status, 401);
});

test('a sniffed proof header cannot be replayed (single-use nonce)', async () => {
  const device = newDevice();
  const { cookie } = await login(device);
  const header = await proof(cookie, device, 'POST /transfer');
  assert.equal((await call(cookie, '/transfer', { method: 'POST', body: { to: 'a', amount: 1 }, headers: { 'x-device-proof': header } })).status, 200);
  const replay = await call(cookie, '/transfer', { method: 'POST', body: { to: 'mallory', amount: 1 }, headers: { 'x-device-proof': header } });
  assert.equal(replay.status, 403);
  assert.ok((await replay.json()).signals.some((s) => s.name === 'proof_expired'));
});

test('a proof for one action cannot authorise another', async () => {
  const device = newDevice();
  const { cookie } = await login(device);
  const forPresence = await proof(cookie, device, 'presence');
  const r = await call(cookie, '/transfer', { method: 'POST', body: { to: 'mallory', amount: 1 }, headers: { 'x-device-proof': forPresence } });
  assert.equal(r.status, 401); // valid signature, wrong purpose: forged-proof class -> terminate
});

test('B2: no unbound sessions, and a key can only be bound by a fresh full login', async () => {
  assert.equal((await login(null)).status, 400); // browser without a device key is refused
  const victim = newDevice();
  const attacker = newDevice();
  const v = await login(victim);
  await login(attacker); // attacker logging in elsewhere (they'd need credentials) gets THEIR OWN new session
  const r = await transferWith(v.cookie, attacker); // ...which does nothing for the victim's session
  assert.equal(r.status, 401);
});

test('the engine service endpoints are not reachable through the app', async () => {
  const { cookie } = await login(newDevice());
  const r = await call(cookie, '/bind', { method: 'POST', body: { public_key: 'x' } });
  assert.ok(r.status === 403 || r.status === 404, `unexpected ${r.status}`);
});
