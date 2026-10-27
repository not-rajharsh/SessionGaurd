'use strict';
/**
 * riskGuard: Express middleware that asks the risk engine about every
 * authenticated request and enforces the verdict.
 *
 *   const guard = createRiskGuard({ engineUrl, apiKey });
 *   app.use(session(...));      // must come first: needs req.session / req.sessionID
 *   app.use(guard.middleware);  // allow -> next(); challenge -> 403; terminate -> 401 + session destroyed
 *   // after login: await guard.evaluate(req)  // registers the session baseline
 *
 * Fails CLOSED (503) if the engine is unreachable or answers nonsense; set
 * failOpen:true only if availability matters more than protection.
 * Client IP comes from req.ip, so configure Express "trust proxy" correctly.
 */
const crypto = require('node:crypto');

const ACTIONS = new Set(['allow', 'challenge', 'terminate']);

const normalizeIp = (ip) => String(ip || '').replace(/^::ffff:/, '');

// Phase 1 passive fingerprint: stable request headers only (User-Agent is a
// separate signal). The client JS agent will supply a richer one later.
function fingerprint(req) {
  const parts = ['accept-language', 'accept-encoding', 'sec-ch-ua-platform'].map((h) => req.get(h) || '');
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

function createRiskGuard({
  engineUrl, apiKey, timeoutMs = 1500, failOpen = false, exposeSignals = false,
  cookieName = 'sid', logger = console,
}) {
  if (!engineUrl || !apiKey) throw new Error('riskGuard: engineUrl and apiKey are required');

  async function evaluate(req) {
    const res = await fetch(`${engineUrl}/evaluate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        session_id: req.sessionID,
        ip: normalizeIp(req.ip),
        user_agent: req.get('user-agent') || '',
        fingerprint_hash: fingerprint(req),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`engine returned HTTP ${res.status}`);
    const verdict = await res.json();
    if (!ACTIONS.has(verdict.action)) throw new Error(`engine returned unknown action ${verdict.action}`);
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

    logger.warn(`[riskGuard] ${verdict.action.toUpperCase()} ${req.method} ${req.originalUrl} score=${verdict.score}`);
    const detail = exposeSignals ? { score: verdict.score, signals: verdict.signals } : {};
    if (verdict.action === 'challenge') {
      return res.status(403).json({
        error: 'step_up_required',
        message: 'Additional verification required (Passkey step-up arrives in a later phase).',
        ...detail,
      });
    }
    return req.session.destroy(() => {
      res.clearCookie(cookieName);
      res.status(401).json({ error: 'session_terminated', message: 'Session terminated due to high risk.', ...detail });
    });
  }

  return { evaluate, middleware };
}

module.exports = { createRiskGuard, fingerprint, normalizeIp };
