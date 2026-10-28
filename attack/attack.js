'use strict';
/**
 * attack.js: the Phase 2 demo. Runs ONLY against our own demo app (refuses non-local hosts).
 *   1. Legitimate user: allowed throughout.
 *   2. Lazy attacker (stolen cookie, different UA and IP): blocked by layer 1.
 *   3. Adaptive attacker (stolen cookie, IDENTICAL UA, headers and IP, no device key): passes
 *      layer 1, stopped by the device-bound proof, fails passkey step-up, session terminated.
 * Network location is simulated by the netsim edge proxy (X-Sim-IP). Signals and rationales are read
 * back from the admin API, i.e. exactly what the dashboard shows. Exit code 0 only if all three hold.
 */
const { launchBrowser, addAuthenticator, sessionRefFromCookie } = require('../scripts/browser');

const LEGIT = { ip: '203.0.113.10', ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36' };
const LAZY = { ip: '198.51.100.20', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0' };
const COPYABLE = ['accept-language', 'accept-encoding', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'];

const line = (s = '') => console.log(s);
const verdict = (ok) => (ok ? 'ALLOWED' : 'BLOCKED');

async function victimLogin(browser, cfg) {
  const ctx = await browser.newContext({ userAgent: LEGIT.ua, locale: 'en-US', extraHTTPHeaders: { 'X-Sim-IP': LEGIT.ip } });
  const page = await ctx.newPage();
  const seen = new Promise((resolve) => page.on('request', (r) => { if (r.isNavigationRequest() && r.url().endsWith('/dashboard')) r.allHeaders().then(resolve); }));
  await page.goto(`${cfg.base}/login`);
  await page.fill('input[name=username]', cfg.user);
  await page.fill('input[name=password]', cfg.password);
  await Promise.all([page.waitForURL('**/dashboard'), page.click('button')]); // creates + binds the device key
  const cookie = (await ctx.cookies()).find((c) => c.name === 'sid');
  return { ctx, page, cookie, headers: await seen, ref: sessionRefFromCookie(cookie.value) };
}

const pageFetch = (page, path, init) => page.evaluate(async ([p, i]) => {
  const r = await fetch(p, i);
  return { status: r.status, body: await r.json().catch(() => ({})) };
}, [path, init]);

async function adminCookie(cfg) {
  const r = await fetch(`${cfg.base}/admin/login`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: cfg.adminUser, password: cfg.adminPassword }) });
  if (r.status !== 302) throw new Error('admin login failed: check ADMIN_USER / ADMIN_PASSWORD in .env');
  return r.headers.getSetCookie()[0].split(';')[0];
}

// The rationale is written asynchronously after the decision, so poll briefly for it.
async function sessionEvents(cfg, cookie, ref) {
  for (let i = 0; i < 40; i++) {
    const { events } = await (await fetch(`${cfg.base}/admin/api/sessions/${ref}`, { headers: { cookie } })).json();
    if (events.every((e) => e.rationale)) return events;
    await new Promise((r) => setTimeout(r, 250));
  }
  return (await (await fetch(`${cfg.base}/admin/api/sessions/${ref}`, { headers: { cookie } })).json()).events;
}

function printBlocked(events) {
  for (const e of events.filter((x) => x.action !== 'allow')) {
    line(`    ${e.action.toUpperCase()}  score ${e.score}/100  (${e.route})`);
    for (const s of e.signals.filter((x) => x.weight !== 0)) line(`      ${s.weight > 0 ? '+' : ''}${s.weight}  ${s.name}: ${s.detail}`);
    const provider = e.provider || e.rationale_source || 'unknown';
    line(`    rationale [${provider}]: ${e.rationale}`);
  }
}

async function scenario1(browser, cfg, admin) {
  line('\n=== 1. Legitimate user ===');
  const v = await victimLogin(browser, cfg);
  line(`  logged in (device key created + bound, IP ${LEGIT.ip})`);
  const me = await pageFetch(v.page, '/api/me', { headers: { accept: 'application/json' } });
  line(`  GET  /api/me    -> ${me.status} ${verdict(me.status === 200)}  (risk: ${me.body.risk && me.body.risk.action}, score ${me.body.risk && me.body.risk.score})`);
  let ok = me.status === 200;
  for (const balance of [9900, 9800]) {
    await v.page.click('#go');
    await v.page.waitForFunction((b) => document.getElementById('out').textContent.includes(`"balance": ${b}`), balance, { timeout: 15000 }).catch(() => {});
    const out = await v.page.textContent('#out');
    line(`  POST /transfer  -> ${out.split(' ')[0]} ${verdict(out.startsWith('200'))}  (own device proof attached)`);
    ok = ok && out.startsWith('200');
  }
  const events = await sessionEvents(cfg, admin, v.ref);
  const allAllowed = events.every((e) => e.action === 'allow');
  line(`  event log: ${events.length} events, ${allAllowed ? 'all allow' : 'NOT all allow'}`);
  await v.ctx.close();
  return { pass: ok && allAllowed, note: `allowed throughout (${events.length} events, max score ${Math.max(...events.map((e) => e.score))})` };
}

async function scenario2(browser, cfg, admin) {
  line('\n=== 2. Lazy attacker: stolen cookie, different User-Agent and IP ===');
  const v = await victimLogin(browser, cfg);
  line(`  victim logged in from ${LEGIT.ip}; attacker copies the cookie ${v.cookie.value.slice(0, 10)}…`);
  const ctx = await browser.newContext({ userAgent: LAZY.ua, extraHTTPHeaders: { 'X-Sim-IP': LAZY.ip } });
  await ctx.addCookies([{ name: v.cookie.name, value: v.cookie.value, url: cfg.base }]);
  const page = await ctx.newPage();
  const resp = await page.goto(`${cfg.base}/dashboard`);
  const blocked = resp.status() === 401;
  line(`  GET  /dashboard -> ${resp.status()} ${verdict(!blocked)}  (Firefox/Windows, IP ${LAZY.ip})`);
  const events = await sessionEvents(cfg, admin, v.ref);
  printBlocked(events);
  const t = events.find((e) => e.action === 'terminate');
  const layer1 = t && t.signals.some((s) => ['user_agent_mismatch', 'ip_change', 'asn_change', 'impossible_travel'].includes(s.name));
  await ctx.close(); await v.ctx.close();
  return { pass: blocked && !!layer1, note: `blocked by layer 1 (terminated, score ${t ? t.score : '?'})` };
}

async function scenario3(browser, cfg, admin) {
  line('\n=== 3. Adaptive attacker: stolen cookie, IDENTICAL UA, headers and IP, no device key ===');
  const v = await victimLogin(browser, cfg);
  const copied = Object.fromEntries(COPYABLE.filter((h) => v.headers[h]).map((h) => [h, v.headers[h]]));
  line(`  attacker copied the cookie, the User-Agent, ${Object.keys(copied).length} request headers and the victim's IP`);
  const ctx = await browser.newContext({ userAgent: LEGIT.ua, extraHTTPHeaders: { ...copied, 'X-Sim-IP': LEGIT.ip } });
  await ctx.addCookies([{ name: v.cookie.name, value: v.cookie.value, url: cfg.base }]);

  const me = await ctx.request.get(`${cfg.base}/api/me`, { headers: { accept: 'application/json' }, maxRedirects: 0 });
  line(`  GET  /api/me    -> ${me.status()} ${verdict(me.status() === 200)}  (layer 1 sees nothing wrong; read inside the 30 s presence window)`);
  const tx = await ctx.request.post(`${cfg.base}/transfer`, { data: { to: 'mallory', amount: 5000 }, maxRedirects: 0 });
  const txBody = await tx.json().catch(() => ({}));
  line(`  POST /transfer  -> ${tx.status()} ${verdict(tx.status() === 200)}  ${txBody.error || ''}  (no device proof)`);

  const page = await ctx.newPage();
  await addAuthenticator(ctx, page); // the attacker's own authenticator: it does not hold the victim's passkey
  await page.goto(`${cfg.base}/stepup`);
  await page.waitForSelector('#status[data-state="failed"], #status[data-state="passed"]', { timeout: 40000 });
  const stepup = await page.getAttribute('#status', 'data-state');
  const reason = await page.getAttribute('#status', 'data-reason');
  const why = reason === 'NotAllowedError' ? 'the attacker\'s authenticator holds no passkey for this account' : 'UNEXPECTED reason';
  line(`  passkey step-up -> ${stepup.toUpperCase()}  (browser reported ${reason || 'nothing'}: ${why})`);
  const after = await ctx.request.get(`${cfg.base}/api/me`, { headers: { accept: 'application/json' }, maxRedirects: 0 });
  line(`  GET  /api/me    -> ${after.status()}  (session terminated)`);

  const events = await sessionEvents(cfg, admin, v.ref);
  printBlocked(events);
  const challenge = events.find((e) => e.action === 'challenge');
  const onlyProof = challenge && challenge.signals.filter((s) => s.weight > 0).every((s) => s.name.startsWith('proof_'));
  const pass = me.status() === 200 && tx.status() === 403 && txBody.error === 'step_up_required' && onlyProof && stepup === 'failed' && reason === 'NotAllowedError' && after.status() === 401;
  await ctx.close(); await v.ctx.close();
  return { pass, note: 'passed layer 1; stopped by the device proof; step-up failed; session terminated' };
}

async function main() {
  require('../scripts/ensure-env').ensureEnv();
  const cfg = {
    base: process.env.BASE_URL || `http://localhost:${process.env.NETSIM_PORT || 3001}`,
    user: process.env.DEMO_USER, password: process.env.DEMO_PASSWORD,
    adminUser: process.env.ADMIN_USER, adminPassword: process.env.ADMIN_PASSWORD,
  };
  if (!['localhost', '127.0.0.1'].includes(new URL(cfg.base).hostname)) throw new Error('refusing to attack a non-local host');
  const admin = await adminCookie(cfg);
  const browser = await launchBrowser();
  const results = [];
  try {
    results.push(['1. Legitimate user', await scenario1(browser, cfg, admin)]);
    results.push(['2. Lazy attacker (different UA + IP)', await scenario2(browser, cfg, admin)]);
    results.push(['3. Adaptive attacker (identical UA/headers/IP, no key)', await scenario3(browser, cfg, admin)]);
  } finally { await browser.close(); }

  line('\n==== SUMMARY ====');
  for (const [name, r] of results) line(`${r.pass ? '✔' : '✘'} ${name}: ${r.pass ? r.note : 'UNEXPECTED RESULT'}`);
  return results.every(([, r]) => r.pass);
}

main().then((ok) => process.exit(ok ? 0 : 1)).catch((e) => { console.error(e); process.exit(1); });
