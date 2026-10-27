'use strict';
/**
 * register-passkey (C1): setup script that registers a passkey for the demo user.
 * Drives the real app (login with device key -> /passkey/setup) in Chromium with a CDP VIRTUAL
 * authenticator, then exports that authenticator's credential to data/demo-authenticator.json so
 * the demo and tests can load it into the legit user's browser later. That file stands in for the
 * user's physical authenticator: it holds a private key, is mode 0600 and git-ignored.
 * Idempotent; `--force` re-registers. Needs the stack running (`npm run engine`, `npm run app`)
 * unless called from `npm run demo`, which does it for you.
 */
const fs = require('node:fs');
const path = require('node:path');
const { ROOT } = require('./ensure-env');
const { launchBrowser, addAuthenticator } = require('./browser');

const AUTH_FILE = path.join(ROOT, 'data', 'demo-authenticator.json');
const defaultStore = () => process.env.PASSKEY_STORE_PATH || path.join(ROOT, 'data', 'passkeys.json');

const loadAuthenticatorCredential = (file = AUTH_FILE) => JSON.parse(fs.readFileSync(file, 'utf8')).credential;

async function registerPasskey({ baseUrl, user, password, force = false, authFile = AUTH_FILE, storeFile = defaultStore() }) {
  if (!force && fs.existsSync(authFile) && fs.existsSync(storeFile)) return { skipped: true, authFile };
  fs.rmSync(authFile, { force: true }); // setup script privilege: start clean (the app itself never replaces a passkey)
  fs.rmSync(storeFile, { force: true });
  const browser = await launchBrowser();
  try {
    const ctx = await browser.newContext({ locale: 'en-US' });
    const page = await ctx.newPage();
    const { cdp, authenticatorId } = await addAuthenticator(ctx, page);
    await page.goto(`${baseUrl}/login`);
    await page.fill('input[name=username]', user);
    await page.fill('input[name=password]', password);
    await Promise.all([page.waitForURL('**/dashboard'), page.click('button')]);
    await page.goto(`${baseUrl}/passkey/setup`);
    await page.click('#register');
    await page.waitForFunction(() => /^(registered|failed)/.test(document.getElementById('status').textContent), null, { timeout: 20000 });
    const status = await page.textContent('#status');
    if (!status.startsWith('registered')) throw new Error(`passkey registration ${status}`);
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    const c = credentials[0];
    fs.mkdirSync(path.dirname(authFile), { recursive: true });
    fs.writeFileSync(authFile, JSON.stringify({
      credential: { credentialId: c.credentialId, isResidentCredential: c.isResidentCredential, rpId: c.rpId, privateKey: c.privateKey, userHandle: c.userHandle, signCount: c.signCount },
    }, null, 2), { mode: 0o600 });
    return { skipped: false, authFile };
  } finally {
    await browser.close();
  }
}

module.exports = { registerPasskey, loadAuthenticatorCredential, AUTH_FILE };

if (require.main === module) {
  require('./ensure-env').ensureEnv();
  registerPasskey({
    baseUrl: process.env.BASE_URL || `http://localhost:${process.env.APP_PORT || 3000}`,
    user: process.env.DEMO_USER, password: process.env.DEMO_PASSWORD, force: process.argv.includes('--force'),
  }).then((r) => console.log(r.skipped ? '[passkey] already registered (use --force to redo)' : `[passkey] registered; authenticator saved to ${r.authFile}`))
    .catch((e) => { console.error(`[passkey] ${e.message}`); process.exit(1); });
}
