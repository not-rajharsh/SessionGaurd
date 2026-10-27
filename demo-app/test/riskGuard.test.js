'use strict';
// Tests for riskGuard: enforcement of allow/challenge/terminate, fail-closed, request payload.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { createRiskGuard, fingerprint } = require('../riskGuard');

const quiet = { error() {}, warn() {} };

function stubEngine(handler) {
  return new Promise((resolve) => {
    const seen = [];
    const srv = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        const body = JSON.parse(raw);
        seen.push({ body, auth: req.headers.authorization });
        const [status, out] = handler(body);
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(out));
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, seen, url: `http://127.0.0.1:${srv.address().port}` }));
  });
}

async function withApp({ verdict, status = 200, loggedIn = true, opts = {} }, fn) {
  const engine = await stubEngine(() => [status, verdict]);
  const guard = createRiskGuard({ engineUrl: engine.url, apiKey: 'k', logger: quiet, exposeSignals: true, ...opts });
  const app = express();
  app.set('trust proxy', true);
  let destroyed = false;
  app.use((req, _res, next) => {
    req.sessionID = 'sess-abcdefgh';
    req.session = { user: loggedIn ? 'demo' : undefined, destroy: (cb) => { destroyed = true; cb(); } };
    next();
  });
  app.use(guard.middleware);
  app.get('/x', (_req, res) => res.json({ reached: true }));
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  try {
    await fn({ base: `http://127.0.0.1:${srv.address().port}`, engine, wasDestroyed: () => destroyed });
  } finally {
    srv.close();
    engine.srv.close();
  }
}

const H = { 'user-agent': 'UA-1', 'x-forwarded-for': '203.0.113.10', 'accept-language': 'en' };

test('allow lets the request through and sends the right payload', async () => {
  await withApp({ verdict: { score: 0, signals: [], action: 'allow' } }, async ({ base, engine }) => {
    const r = await fetch(`${base}/x`, { headers: H });
    assert.equal(r.status, 200);
    const { body, auth } = engine.seen[0];
    assert.equal(auth, 'Bearer k');
    assert.equal(body.session_id, 'sess-abcdefgh');
    assert.equal(body.ip, '203.0.113.10');
    assert.equal(body.user_agent, 'UA-1');
    assert.match(body.fingerprint_hash, /^[0-9a-f]{64}$/);
  });
});

test('challenge returns 403 and does not destroy the session', async () => {
  const verdict = { score: 40, signals: [{ name: 'user_agent_mismatch' }], action: 'challenge' };
  await withApp({ verdict }, async ({ base, wasDestroyed }) => {
    const r = await fetch(`${base}/x`, { headers: H });
    assert.equal(r.status, 403);
    assert.equal((await r.json()).error, 'step_up_required');
    assert.equal(wasDestroyed(), false);
  });
});

test('terminate returns 401, destroys the session, and exposes signals only when enabled', async () => {
  const verdict = { score: 100, signals: [{ name: 'impossible_travel' }], action: 'terminate' };
  await withApp({ verdict }, async ({ base, wasDestroyed }) => {
    const r = await fetch(`${base}/x`, { headers: H });
    const j = await r.json();
    assert.equal(r.status, 401);
    assert.equal(j.error, 'session_terminated');
    assert.equal(j.signals[0].name, 'impossible_travel');
    assert.equal(wasDestroyed(), true);
  });
  await withApp({ verdict, opts: { exposeSignals: false } }, async ({ base }) => {
    const j = await (await fetch(`${base}/x`, { headers: H })).json();
    assert.equal(j.signals, undefined);
  });
});

test('unauthenticated requests skip the engine entirely', async () => {
  await withApp({ verdict: { action: 'terminate' }, loggedIn: false }, async ({ base, engine }) => {
    assert.equal((await fetch(`${base}/x`)).status, 200);
    assert.equal(engine.seen.length, 0);
  });
});

test('fails closed (503) when the engine errors, open only if configured', async () => {
  await withApp({ verdict: { error: 'boom' }, status: 500 }, async ({ base }) => {
    assert.equal((await fetch(`${base}/x`, { headers: H })).status, 503);
  });
  await withApp({ verdict: { error: 'boom' }, status: 500, opts: { failOpen: true } }, async ({ base }) => {
    assert.equal((await fetch(`${base}/x`, { headers: H })).status, 200);
  });
  await withApp({ verdict: { action: 'bogus' } }, async ({ base }) => {
    assert.equal((await fetch(`${base}/x`, { headers: H })).status, 503);
  });
});

test('fingerprint ignores User-Agent but changes with other headers', () => {
  const mk = (h) => ({ get: (n) => h[n] });
  const a = fingerprint(mk({ 'accept-language': 'en', 'user-agent': 'A' }));
  assert.equal(a, fingerprint(mk({ 'accept-language': 'en', 'user-agent': 'B' })));
  assert.notEqual(a, fingerprint(mk({ 'accept-language': 'fr' })));
});
