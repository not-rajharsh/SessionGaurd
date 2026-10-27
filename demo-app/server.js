'use strict';
/**
 * demo-app: the protected app. Login (single demo user from .env), dashboard,
 * and a fake "transfer money" action. Sessions live in Redis (connect-redis).
 * Every authenticated request passes through riskGuard before any route runs.
 * createApp() takes an injectable session store so tests can run without Redis.
 */
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const { createRiskGuard } = require('./riskGuard');

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

const page = (title, body) => `<!doctype html><meta charset="utf-8"><title>${esc(title)}</title>
<style>body{font:16px system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem}input,button{font:inherit;padding:.4rem;margin:.2rem 0}
pre{background:#f4f4f4;padding:.6rem;overflow:auto}.err{color:#b00020}</style>${body}`;

function parseTrustProxy(v) {
  if (v === 'true') return true;
  if (v && /^\d+$/.test(v)) return Number(v);
  return false;
}

function createApp({ store, env = process.env }) {
  for (const k of ['SESSION_SECRET', 'ENGINE_API_KEY', 'DEMO_USER', 'DEMO_PASSWORD', 'RISK_ENGINE_URL']) {
    if (!env[k]) throw new Error(`${k} is not set (see .env.example)`);
  }
  const guard = createRiskGuard({
    engineUrl: env.RISK_ENGINE_URL,
    apiKey: env.ENGINE_API_KEY,
    exposeSignals: env.EXPOSE_SIGNALS === 'true',
  });
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', parseTrustProxy(env.TRUST_PROXY));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(session({
    name: 'sid', store, secret: env.SESSION_SECRET, resave: false, saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 },
  }));
  app.use(guard.middleware);

  const requireLogin = (req, res, next) => {
    if (req.session.user) return next();
    const isPageLoad = req.method === 'GET' && req.accepts(['html', 'json']) === 'html';
    return isPageLoad ? res.redirect('/login') : res.status(401).json({ error: 'login_required' });
  };

  const loginForm = (msg = '') => page('Login', `<h1>Demo bank</h1>${msg ? `<p class="err">${esc(msg)}</p>` : ''}
<form method="post" action="/login"><label>User <input name="username" autocomplete="username"></label><br>
<label>Password <input name="password" type="password" autocomplete="current-password"></label><br><button>Log in</button></form>`);

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));
  app.get('/login', (_req, res) => res.send(loginForm()));

  app.post('/login', (req, res, next) => {
    const { username = '', password = '' } = req.body || {};
    // Evaluate both comparisons so timing doesn't reveal which one failed.
    const ok = safeEqual(username, env.DEMO_USER) & safeEqual(password, env.DEMO_PASSWORD);
    if (!ok) return res.status(401).send(loginForm('Invalid credentials'));
    req.session.regenerate(async (err) => { // fresh session id: no fixation
      if (err) return next(err);
      req.session.user = env.DEMO_USER;
      req.session.balance = 10000;
      try {
        await guard.evaluate(req); // first call for this session id = baseline
      } catch (e) {
        return req.session.destroy(() => res.status(503).send(loginForm('Risk engine unavailable')));
      }
      return req.session.save((e) => (e ? next(e) : res.redirect('/dashboard')));
    });
  });

  app.post('/logout', (req, res) => req.session.destroy(() => { res.clearCookie('sid'); res.redirect('/login'); }));

  app.get('/api/me', requireLogin, (req, res) => res.json({ user: req.session.user, balance: req.session.balance, risk: req.risk }));

  app.get('/dashboard', requireLogin, (req, res) => res.send(page('Dashboard', `
<h1>Welcome, ${esc(req.session.user)}</h1><p>Balance: $<span id="bal">${req.session.balance}</span> (fake)</p>
<h2>Transfer</h2><input id="to" placeholder="Recipient" value="alice"> <input id="amt" type="number" value="100"> <button id="go">Send</button>
<pre id="out">(no transfer yet)</pre>
<form method="post" action="/logout"><button>Log out</button></form>
<script>document.getElementById('go').onclick=async()=>{
 const r=await fetch('/transfer',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({to:to.value,amount:Number(amt.value)})});
 const j=await r.json();out.textContent=r.status+' '+JSON.stringify(j,null,2);if(j.balance!=null)bal.textContent=j.balance;};</script>`)));

  app.post('/transfer', requireLogin, (req, res) => {
    const { to, amount } = req.body || {};
    if (typeof to !== 'string' || !to || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'bad_request' });
    if (amount > req.session.balance) return res.status(400).json({ error: 'insufficient_funds' });
    req.session.balance -= amount;
    return res.json({ ok: true, message: `Transferred $${amount} to ${to} (demo: no money moved)`, balance: req.session.balance });
  });

  app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'internal_error' }); });
  return app;
}

async function main() {
  require(path.join(__dirname, '..', 'scripts', 'ensure-env.js')).ensureEnv();
  const { createClient } = require('redis');
  const RedisStore = require('connect-redis').default;
  const client = createClient({ url: process.env.REDIS_URL });
  client.on('error', (e) => console.error('[redis]', e.message));
  await client.connect();
  const app = createApp({ store: new RedisStore({ client, prefix: 'sess:' }) });
  const port = Number(process.env.APP_PORT || 3000);
  app.listen(port, '127.0.0.1', () => console.log(`[app] listening on http://127.0.0.1:${port}`));
}

module.exports = { createApp };
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
