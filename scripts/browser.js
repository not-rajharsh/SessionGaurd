'use strict';
// browser helpers shared by the attack demo, the passkey setup script and the browser tests.
const crypto = require('node:crypto');
const { chromium } = require('playwright');

// PW_CHROMIUM_PATH lets you use a pre-installed Chromium when Playwright's download is blocked.
const launchBrowser = () => chromium.launch({ executablePath: process.env.PW_CHROMIUM_PATH || undefined });

// C4: Chromium's CDP virtual authenticator (no hardware needed). Optionally pre-loads a credential.
async function addAuthenticator(context, page, credential) {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  if (credential) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { cdp, authenticatorId };
}

// Same short hash the engine shows instead of the real (secret) session id.
function sessionRefFromCookie(value) {
  const sid = decodeURIComponent(value).replace(/^s:/, '').replace(/\.[^.]+$/, '');
  return crypto.createHash('sha256').update(sid).digest('hex').slice(0, 12);
}

module.exports = { launchBrowser, addAuthenticator, sessionRefFromCookie };
