'use strict';
/**
 * riskGuard: Express middleware that asks the risk engine about every
 * authenticated request and enforces the verdict.
 *
 *   const guard = createRiskGuard({ engineUrl, apiKey });
 *   app.use(session(...));      // first: needs req.session / req.sessionID
 *   app.use(guard.middleware);  // allow -> next(); challenge -> 403 (+ passkey step-up page for
 *                               // browsers); terminate -> 401 + session destroyed
 *   // login handler: await guard.evaluate(req) registers the session baseline
 *
 * Request kinds sent to the engine: "auth" (login/logout/challenge/presence/step-up plumbing,
 * which must stay reachable), "write" (any non-GET: needs its own device proof) and "read".
 * The client's device proof travels in `X-Device-Proof: <nonce>.<signature>`; the purpose it
 * signed is derived HERE from the real request ("presence" or "<METHOD> <path>").
 * Fails CLOSED (503) if the engine is unreachable; failOpen:true only if you accept the risk.
 * Client IP comes from req.ip, so configure Express "trust proxy" (see trustProxy.js).
 */
const crypto = require('node:crypto');
const { createEngineClient } = require('./engineClient');
const { stepupPage } = require('./views');

const ACTIONS = new Set(['allow', 'challenge', 'terminate']);
const AUTH_PATHS = new Set(['/login', '/logout', '/stepup']);

const normalizeIp = (ip) => String(ip || '').replace(/^::ffff:/, '');

// Phase 1 passive fingerprint: stable request headers only (User-Agent is a separate signal).
// WEAK: anyone who has seen or copies these headers reproduces it, so the engine gives it a low weight.
function fingerprint(req) {
  const parts = ['accept-language', 'accept-encoding', 'sec-ch-ua-platform'].map((h) => req.get(h) || '');
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

function classify(req) {
  const p = req.path || '/';
  if (AUTH_PATHS.has(p) || p.startsWith('/auth/') || p.startsWith('/stepup/')) return 'auth';
  return ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ? 'read' : 'write';
}

function proofFields(req) {
  const h = req.get('x-device-proof');
  if (!h) return {};
  const [nonce, signature] = h.slice(0, 400).split('.');
  return {
    proof_nonce: (nonce || '-').slice(0, 128),
    proof_signature: (signature || '-').slice(0, 256),
    proof_purpose: (req.path === '/auth/presence' ? 'presence' : `${req.method} ${req.path}`).slice(0, 256),
  };
}

const wantsHtml = (req) => req.method === 'GET' && (req.get('accept') || '').includes('text/html');

function createRiskGuard({
  engineUrl, apiKey, engine, timeoutMs = 1500, failOpen = false, exposeSignals = false,
  cookieName = 'sid', logger = console,
}) {
  const client = engine || createEngineClient({ engineUrl, apiKey, timeoutMs });

  const context = (req) => ({
    session_id: req.sessionID,
    ip: normalizeIp(req.ip),
    user_agent: req.get('user-agent') || '',
    fingerprint_hash: fingerprint(req),
  });

  async function evaluate(req) {
    const verdict = await client.evaluate({
      ...context(req), kind: classify(req), route: `${req.method} ${req.path}`.slice(0, 300), ...proofFields(req),
    });
    if (!verdict || !ACTIONS.has(verdict.action)) throw new Error(`engine returned unknown action ${verdict && verdict.action}`);
    return verdict;
  }

  async function middleware(req, res, next) {
    if (!req.session || !req.session.user) return next(); // only authenticated requests
    let verdict;
    try {
      verdict = await evaluate(req);
    } catch (err) {
      logger.error(`[riskGuard] engine error: ${err.message}`);
      return failOpen ? next() : res.status(503).json({ error: 'risk_engine_unavailable' });
    }
    req.risk = verdict;
    if (verdict.action === 'allow') return next();

    const kind = classify(req);
    logger.warn(`[riskGuard] ${verdict.action.toUpperCase()} ${req.method} ${req.originalUrl} score=${verdict.score}`);
    const detail = exposeSignals ? { score: verdict.score, signals: verdict.signals } : {};
    if (verdict.action === 'challenge') {
      if (kind === 'auth') return next(); // step-up and proof plumbing must stay reachable
      if (wantsHtml(req)) return res.status(403).type('html').send(stepupPage());
      return res.status(403).json({
        error: 'step_up_required', stepup_url: '/stepup',
        message: 'Passkey step-up required. Complete it, then retry.', ...detail,
      });
    }
    return req.session.destroy(() => {
      res.clearCookie(cookieName);
      res.status(401).json({ error: 'session_terminated', message: 'Session terminated due to high risk.', ...detail });
    });
  }

  return { evaluate, middleware, context, engine: client };
}

module.exports = { createRiskGuard, fingerprint, normalizeIp, classify };
