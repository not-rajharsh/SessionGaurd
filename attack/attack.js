'use strict';
/**
 * attack.js: session-replay demo. Runs ONLY against our own demo app
 * (refuses any host other than localhost / 127.0.0.1).
 *   Browser A (legit user): logs in, uses the app           -> must be ALLOWED
 *   Attacker: copies A's session cookie out of the browser
 *   Browser B (fresh context, different User-Agent, spoofed
 *     X-Forwarded-For): replays the cookie                  -> must be BLOCKED
 * Prints the verdicts and fired signals; exit code 0 only if both hold.
 * Set PW_CHROMIUM_PATH to use a pre-installed Chromium instead of Playwright's.
 */
const { chromium } = require('playwright');

const LEGIT = { ip: '203.0.113.10', ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36' };
const ATTACKER = { ip: '198.51.100.20', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0' };

const tag = (ok) => (ok ? 'ALLOWED' : 'BLOCKED');

function printSignals(body) {
  if (!body || !body.signals) return;
  console.log(`      score=${body.score}`);
  for (const s of body.signals) console.log(`      - ${s.name} (+${s.weight}): ${s.detail}`);
}

async function run({ baseUrl, user, password }) {
  const host = new URL(baseUrl).hostname;
  if (!['127.0.0.1', 'localhost'].includes(host)) throw new Error(`refusing to attack non-local host ${host}`);

  const browser = await chromium.launch({ executablePath: process.env.PW_CHROMIUM_PATH || undefined });
  const result = { legitAllowed: false, replayBlocked: false };
  try {
    // ---- Browser A: the legitimate user -------------------------------------------
    const ctxA = await browser.newContext({ userAgent: LEGIT.ua, locale: 'en-US', extraHTTPHeaders: { 'X-Forwarded-For': LEGIT.ip } });
    const pageA = await ctxA.newPage();
    await pageA.goto(`${baseUrl}/login`);
    await pageA.fill('input[name=username]', user);
    await pageA.fill('input[name=password]', password);
    await Promise.all([pageA.waitForURL('**/dashboard'), pageA.click('button')]);
    console.log(`[A] logged in as "${user}"  (IP ${LEGIT.ip}, Chrome/Linux)`);

    const call = (page, path, init) => page.evaluate(async ([p, i]) => {
      const r = await fetch(p, i);
      return { status: r.status, body: await r.json() };
    }, [path, init]);

    const me = await call(pageA, '/api/me', { headers: { accept: 'application/json' } });
    const tx = await call(pageA, '/transfer', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ to: 'alice', amount: 100 }) });
    result.legitAllowed = me.status === 200 && me.body.risk?.action === 'allow' && tx.status === 200;
    console.log(`[A] GET  /api/me    -> ${me.status} ${tag(me.status === 200)}  (risk: ${me.body.risk?.action}, score ${me.body.risk?.score})`);
    console.log(`[A] POST /transfer  -> ${tx.status} ${tag(tx.status === 200)}  ${tx.body.message || ''}`);

    // ---- The theft: copy the session cookie out of A -------------------------------
    const stolen = (await ctxA.cookies()).find((c) => c.name === 'sid');
    console.log(`\n[attacker] stole session cookie sid=${stolen.value.slice(0, 8)}… from browser A\n`);

    // ---- Browser B: fresh context, other UA, spoofed network -----------------------
    const ctxB = await browser.newContext({ userAgent: ATTACKER.ua, extraHTTPHeaders: { 'X-Forwarded-For': ATTACKER.ip } });
    await ctxB.addCookies([{ name: stolen.name, value: stolen.value, url: baseUrl }]);
    const pageB = await ctxB.newPage();
    const resp = await pageB.goto(`${baseUrl}/dashboard`);
    let body1 = null;
    try { body1 = JSON.parse(await resp.text()); } catch { /* HTML means we got in */ }
    const blocked1 = resp.status() !== 200;
    console.log(`[B] GET  /dashboard -> ${resp.status()} ${tag(!blocked1)}  (IP ${ATTACKER.ip}, Firefox/Windows)`);
    if (body1) { console.log(`      ${body1.error}: ${body1.message}`); printSignals(body1); }

    const tx2 = await ctxB.request.post(`${baseUrl}/transfer`, { data: { to: 'mallory', amount: 5000 }, maxRedirects: 0 });
    const tx2Body = await tx2.json().catch(() => ({}));
    const blocked2 = !(tx2.status() === 200 && tx2Body.ok === true);
    console.log(`[B] POST /transfer  -> ${tx2.status()} ${tag(!blocked2)}  (cookie is dead after termination)`);
    result.replayBlocked = blocked1 && blocked2;

    // ---- Consequence for the real user ----------------------------------------------
    const after = await call(pageA, '/api/me', { headers: { accept: 'application/json' } });
    console.log(`[A] GET  /api/me    -> ${after.status}  (session was terminated for everyone; user must log in again)`);
  } finally {
    await browser.close();
  }

  console.log('\n==== RESULT ====');
  console.log(`legit session:    ${result.legitAllowed ? 'ALLOWED  ✔' : 'NOT ALLOWED  ✘'}`);
  console.log(`replayed session: ${result.replayBlocked ? 'BLOCKED  ✔' : 'NOT BLOCKED  ✘'}`);
  return result;
}

module.exports = { run };

if (require.main === module) {
  require('../scripts/ensure-env').ensureEnv();
  const baseUrl = process.env.BASE_URL || `http://127.0.0.1:${process.env.APP_PORT || 3000}`;
  run({ baseUrl, user: process.env.DEMO_USER, password: process.env.DEMO_PASSWORD })
    .then((r) => { process.exitCode = r.legitAllowed && r.replayBlocked ? 0 : 1; })
    .catch((e) => { console.error(e); process.exitCode = 1; });
}
