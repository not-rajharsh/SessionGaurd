'use strict';
// A1: X-Forwarded-For must NOT be trusted blindly. The IP the engine sees comes from the socket
// unless the TCP peer is a configured trusted proxy, and then only the right-most untrusted hop counts.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const session = require('express-session');
const { createApp } = require('../server');
const { parseTrustProxy } = require('../trustProxy');

function stubEngine() {
  return new Promise((resolve) => {
    const seen = [];
    const srv = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        if (req.url === '/evaluate') seen.push(JSON.parse(raw));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(req.url === '/evaluate' ? { score: 0, signals: [], action: 'allow' } : { bound: true }));
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, seen, url: `http://127.0.0.1:${srv.address().port}` }));
  });
}

// Logs in (which makes the app call /evaluate) and returns the IP the engine was told.
async function ipSeenByEngine(trust, xff) {
  const engine = await stubEngine();
  const env = { SESSION_SECRET: 's', ENGINE_API_KEY: 'k', DEMO_USER: 'demo', DEMO_PASSWORD: 'pw', RISK_ENGINE_URL: engine.url, REQUIRE_DEVICE_KEY: 'false' };
  if (trust !== undefined) env.TRUST_PROXY = trust;
  const app = createApp({ store: new session.MemoryStore(), env });
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const headers = { 'content-type': 'application/x-www-form-urlencoded' };
    if (xff) headers['x-forwarded-for'] = xff;
    const r = await fetch(`http://127.0.0.1:${srv.address().port}/login`, { method: 'POST', redirect: 'manual', headers, body: 'username=demo&password=pw' });
    assert.equal(r.status, 302);
    return engine.seen[0].ip;
  } finally { srv.close(); engine.srv.close(); }
}

test('default: a spoofed X-Forwarded-For does NOT change the IP the engine sees', async () => {
  assert.equal(await ipSeenByEngine(undefined, '198.51.100.20'), '127.0.0.1');
  assert.equal(await ipSeenByEngine('', '198.51.100.20, 203.0.113.9'), '127.0.0.1');
  assert.equal(await ipSeenByEngine('false', '6.6.6.6'), '127.0.0.1');
});

test('XFF from a peer that is not a trusted proxy is ignored', async () => {
  assert.equal(await ipSeenByEngine('10.0.0.0/8', '198.51.100.20'), '127.0.0.1'); // peer is 127.0.0.1, not in 10/8
});

test('XFF is honoured when the peer is a trusted proxy', async () => {
  assert.equal(await ipSeenByEngine('loopback', '203.0.113.10'), '203.0.113.10');
  assert.equal(await ipSeenByEngine('127.0.0.1', '203.0.113.10'), '203.0.113.10');
});

test('entries a client prepends to X-Forwarded-For never win over the proxy-appended address', async () => {
  assert.equal(await ipSeenByEngine('loopback', '6.6.6.6, 203.0.113.10'), '203.0.113.10');
});

test('parseTrustProxy: rejects hop counts and garbage, maps "true" to loopback with a warning', () => {
  assert.equal(parseTrustProxy(undefined), false);
  assert.equal(parseTrustProxy('  '), false);
  assert.deepEqual(parseTrustProxy('loopback, 10.0.0.0/8, ::1'), ['loopback', '10.0.0.0/8', '::1']);
  assert.throws(() => parseTrustProxy('1'), /hop count/);
  assert.throws(() => parseTrustProxy('not-an-ip'), /invalid entry/);
  assert.throws(() => parseTrustProxy('10.0.0.0/99'), /invalid entry/);
  const warned = [];
  assert.deepEqual(parseTrustProxy('true', (m) => warned.push(m)), ['loopback']);
  assert.equal(warned.length, 1);
});
