'use strict';
// E2: attacker-controlled User-Agents must render as inert TEXT on the admin dashboard.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { startStack } = require('../scripts/stack');
const { launchBrowser } = require('../scripts/browser');

const PAYLOADS = [
  '<img src=x onerror="window.__xss=1">',
  '"><script>window.__xss=1</script>',
  '<svg/onload=window.__xss=1>',
];
let stack, browser;
test.before(async () => { stack = await startStack(); browser = await launchBrowser(); });
test.after(async () => { await browser?.close(); stack?.stop(); });

test('XSS payloads in the User-Agent do not execute or become markup on the dashboard', { timeout: 90000 }, async () => {
  // Put the payloads into the event log the way an attacker would: through the User-Agent header.
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const login = await fetch(`${stack.direct}/login`, { method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': PAYLOADS[0] },
    body: new URLSearchParams({ username: 'demo', password: stack.env.DEMO_PASSWORD, pubkey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') }) });
  const cookie = login.headers.getSetCookie()[0].split(';')[0];
  for (const ua of PAYLOADS.slice(1)) await fetch(`${stack.direct}/api/me`, { headers: { cookie, 'user-agent': ua, accept: 'application/json' } });

  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  let dialogs = 0;
  page.on('dialog', async (d) => { dialogs += 1; await d.dismiss(); });
  await page.goto(`${stack.base}/admin/login`);
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', stack.env.ADMIN_PASSWORD);
  await Promise.all([page.waitForURL('**/admin'), page.click('button')]);
  await page.waitForSelector('#sessions tbody tr.row');
  await page.click('#sessions tbody tr.row');
  await page.waitForSelector('#events .ev');
  await page.waitForTimeout(500); // let any (unwanted) handler fire

  const text = await page.textContent('#events');
  for (const p of PAYLOADS) assert.ok(text.includes(p.slice(0, 20)), `payload shown as text: ${p}`);
  assert.equal(await page.evaluate(() => window.__xss), undefined, 'no script ran');
  assert.equal(dialogs, 0);
  // Structurally inert: the payload never became elements.
  assert.equal(await page.locator('#events img, #events script, #events svg[onload], #events [onerror]').count(), 0);
  assert.equal(await page.locator('#sessions img, #sessions script').count(), 0);
  await ctx.close();
});

function startLlmStub(content) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ choices: [{ message: { content } }] }));
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${srv.address().port}/v1`,
      close: () => new Promise((r) => srv.close(r)),
    }));
  });
}

test('an XSS payload in a stored rationale stays inert text on /admin', { timeout: 90000 }, async () => {
  const payload = '<img src=x onerror="window.__xss=1">';
  const llm = await startLlmStub(payload);
  const local = await startStack({ engineEnv: {
    LLM_PROVIDER: 'openai_compatible', LLM_BASE_URL: llm.url, LLM_MODEL: 'stub', LLM_API_KEY: 'k', LLM_TIMEOUT_SECONDS: '2',
  } });
  let ctx;
  try {
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const login = await fetch(`${local.direct}/login`, { method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'demo', password: local.env.DEMO_PASSWORD, pubkey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') }) });
    const cookie = login.headers.getSetCookie()[0].split(';')[0];
    // Different UA -> a signal fires -> the engine asks the stub LLM for a rationale (the payload).
    await fetch(`${local.direct}/api/me`, { headers: { cookie, accept: 'application/json',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Firefox/120 Attacker' } });

    ctx = await browser.newContext();
    const page = await ctx.newPage();
    let dialogs = 0;
    page.on('dialog', async (d) => { dialogs += 1; await d.dismiss(); });
    await page.goto(`${local.base}/admin/login`);
    await page.fill('input[name=username]', 'admin');
    await page.fill('input[name=password]', local.env.ADMIN_PASSWORD);
    await Promise.all([page.waitForURL('**/admin'), page.click('button')]);
    await page.waitForSelector('#sessions tbody tr.row');
    await page.click('#sessions tbody tr.row');
    await page.waitForFunction((p) => document.querySelector('#events')?.textContent.includes(p),
      payload.slice(0, 20), { timeout: 15000 });
    await page.waitForTimeout(300);

    assert.ok((await page.textContent('#events')).includes(payload));
    assert.equal(await page.evaluate(() => window.__xss), undefined, 'no script ran');
    assert.equal(dialogs, 0);
    assert.equal(await page.locator('#events img, #events script, #events [onerror]').count(), 0);
  } finally {
    await ctx?.close();
    local.stop();
    await llm.close();
  }
});
