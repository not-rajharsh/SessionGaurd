'use strict';
// C4: passkey step-up tested end to end in Chromium with a CDP VIRTUAL authenticator (no hardware).
// The engine runs with a 10 s presence window so a short pause makes the device proof stale and the
// next page load is challenged for real. Needs Chromium (npm run setup, or set PW_CHROMIUM_PATH).
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { startStack } = require('../scripts/stack');
const { launchBrowser, addAuthenticator } = require('../scripts/browser');
const { registerPasskey, loadAuthenticatorCredential } = require('../scripts/register-passkey');

let stack, browser, authFile;
test.before(async () => {
  stack = await startStack({ engineEnv: { PROOF_MAX_AGE_SECONDS: '10' } });
  authFile = path.join(stack.tmp, 'authenticator.json');
  await registerPasskey({ baseUrl: stack.base, user: 'demo', password: stack.env.DEMO_PASSWORD, authFile, storeFile: stack.env.PASSKEY_STORE_PATH });
  browser = await launchBrowser();
});
test.after(async () => { await browser?.close(); stack?.stop(); });

async function loginPage({ withPasskey }) {
  const ctx = await browser.newContext({ locale: 'en-US' });
  const page = await ctx.newPage();
  await addAuthenticator(ctx, page, withPasskey ? loadAuthenticatorCredential(authFile) : undefined);
  await page.goto(`${stack.base}/login`);
  await page.fill('input[name=username]', 'demo');
  await page.fill('input[name=password]', stack.env.DEMO_PASSWORD);
  await Promise.all([page.waitForURL('**/dashboard'), page.click('button')]);
  return { ctx, page };
}

async function events() {
  const login = await fetch(`${stack.direct}/admin/login`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ username: 'admin', password: stack.env.ADMIN_PASSWORD }) });
  const cookie = login.headers.getSetCookie()[0].split(';')[0];
  const { sessions } = await (await fetch(`${stack.direct}/admin/api/sessions`, { headers: { cookie } })).json();
  const all = await Promise.all(sessions.map(async (s) => (await (await fetch(`${stack.direct}/admin/api/sessions/${s.ref}`, { headers: { cookie } })).json()).events));
  return all.flat();
}

test('legit user with the registered passkey: challenged, step-up passes, elevated window applies', { timeout: 90000 }, async () => {
  const { ctx, page } = await loginPage({ withPasskey: true });
  await page.waitForTimeout(11000); // device proof is now older than the 10 s window
  await page.goto(`${stack.base}/dashboard`); // challenged -> step-up page -> real WebAuthn assertion -> back to dashboard
  await page.waitForSelector('h1:has-text("Welcome, demo")', { timeout: 30000 });
  const names = (await events()).flatMap((e) => e.signals.map((s) => s.name));
  assert.ok(names.includes('proof_stale'), 'the load was challenged because the device proof was stale');
  assert.ok(names.includes('stepup_passed'), 'the passkey assertion was verified');
  assert.ok(names.includes('stepup_elevated'), 'the follow-up request was allowed by the elevated-trust window');
  assert.equal((await page.evaluate(() => fetch('/api/me', { headers: { accept: 'application/json' } }).then((r) => r.status))), 200);
  await ctx.close();
});

test('without the victim\'s passkey: step-up fails and the session is terminated', { timeout: 90000 }, async () => {
  const { ctx, page } = await loginPage({ withPasskey: false });
  await page.waitForTimeout(11000);
  await page.goto(`${stack.base}/dashboard`);
  await page.waitForSelector('#status[data-state="failed"]', { timeout: 40000 });
  assert.equal(await page.getAttribute('#status', 'data-reason'), 'NotAllowedError');
  const me = await page.evaluate(() => fetch('/api/me', { headers: { accept: 'application/json' } }).then((r) => r.status));
  assert.equal(me, 401); // session terminated
  const names = (await events()).flatMap((e) => e.signals.map((s) => s.name));
  assert.ok(names.includes('stepup_failed'));
  await ctx.close();
});

test('a passkey cannot be added or replaced by an unproven request', { timeout: 60000 }, async () => {
  const { ctx, page } = await loginPage({ withPasskey: true });
  // Already registered: even a fully proven request is refused (409); an unproven one never gets that far.
  const r = await page.evaluate(() => SG.fetchWithProof('/passkey/register/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }).then((x) => x.status));
  assert.equal(r, 409);
  const raw = await page.evaluate(() => fetch('/passkey/register/options', { method: 'POST' }).then((x) => x.status));
  assert.equal(raw, 403); // no device proof -> step-up required
  await ctx.close();
});
