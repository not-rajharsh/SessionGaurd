'use strict';
// E1 access control + server-side hardening of the /admin dashboard.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startStack } = require('../../scripts/stack');

const form = (o) => ({ method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o) });
let stack;
test.before(async () => { stack = await startStack(); });
test.after(() => stack.stop());

async function adminCookie() {
  const r = await fetch(`${stack.direct}/admin/login`, form({ username: 'admin', password: stack.env.ADMIN_PASSWORD }));
  assert.equal(r.status, 302);
  return r.headers.getSetCookie()[0].split(';')[0];
}

test('admin pages and API require the admin login', async () => {
  const page = await fetch(`${stack.direct}/admin`, { redirect: 'manual' });
  assert.equal(page.status, 302);
  assert.equal(page.headers.get('location'), '/admin/login');
  assert.equal((await fetch(`${stack.direct}/admin/api/sessions`)).status, 401);
  assert.equal((await fetch(`${stack.direct}/admin/login`, form({ username: 'admin', password: 'wrong' }))).status, 401);
});

test('a normal user session does not grant admin', async () => {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const login = await fetch(`${stack.direct}/login`, form({ username: 'demo', password: stack.env.DEMO_PASSWORD, pubkey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') }));
  const userCookie = login.headers.getSetCookie()[0].split(';')[0];
  const r = await fetch(`${stack.direct}/admin/api/sessions`, { headers: { cookie: userCookie } });
  assert.equal(r.status, 401);
});

test('admin sees sessions without any raw session id; page ships a CSP and no inline script', async () => {
  const cookie = await adminCookie();
  const list = await fetch(`${stack.direct}/admin/api/sessions`, { headers: { cookie } });
  assert.equal(list.status, 200);
  const { sessions } = await list.json();
  assert.ok(sessions.length >= 1 && sessions.every((s) => /^[0-9a-f]{12}$/.test(s.ref)));
  const detail = await fetch(`${stack.direct}/admin/api/sessions/${sessions[0].ref}`, { headers: { cookie } });
  assert.equal(detail.status, 200);
  assert.equal((await fetch(`${stack.direct}/admin/api/sessions/not-a-ref`, { headers: { cookie } })).status, 400);

  const html = await fetch(`${stack.direct}/admin`, { headers: { cookie } });
  assert.match(html.headers.get('content-security-policy'), /script-src 'self'/);
  assert.doesNotMatch(await html.text(), /<script(?![^>]*\ssrc=)[^>]*>/); // only <script src=...>
});

test('admin is disabled when no admin password is configured', async () => {
  const off = await startStack({ appEnv: { ADMIN_PASSWORD: '' } });
  try {
    assert.equal((await fetch(`${off.direct}/admin/login`)).status, 404);
  } finally { off.stop(); }
});
