'use strict';
/**
 * trustProxy: parses TRUST_PROXY for Express' "trust proxy" setting.
 *
 * Default (unset / "false"): X-Forwarded-For is IGNORED and the socket address is
 * used. Otherwise the value is a comma-separated list of trusted proxy IPs / CIDRs
 * (or loopback | linklocal | uniquelocal). X-Forwarded-For is read only when the
 * TCP peer is one of those, and Express then walks the header from the right, so
 * spoofed entries added by the client (to the left) are never used.
 * Rejected on purpose: hop counts (they trust the header even with no proxy in
 * front) and "true" (trusts everyone). "true" is mapped to loopback with a warning
 * so Phase 1 .env files keep working safely.
 */
const net = require('node:net');

const NAMED = new Set(['loopback', 'linklocal', 'uniquelocal']);

function validEntry(tok) {
  if (NAMED.has(tok)) return true;
  const [ip, bits, ...rest] = tok.split('/');
  if (rest.length || !net.isIP(ip)) return false;
  if (bits === undefined) return true;
  return /^\d+$/.test(bits) && Number(bits) <= (net.isIPv4(ip) ? 32 : 128);
}

function parseTrustProxy(raw, warn = console.warn) {
  const v = String(raw ?? '').trim();
  if (v === '' || v.toLowerCase() === 'false') return false;
  if (v.toLowerCase() === 'true') {
    warn('[config] TRUST_PROXY=true would trust every sender; treating it as "loopback". Set an explicit list of proxy IPs/CIDRs.');
    return ['loopback'];
  }
  const tokens = v.split(',').map((t) => t.trim()).filter(Boolean);
  for (const t of tokens) {
    if (/^\d+$/.test(t)) throw new Error(`TRUST_PROXY: hop count "${t}" is not accepted; list the proxy IPs/CIDRs instead`);
    if (!validEntry(t)) throw new Error(`TRUST_PROXY: invalid entry "${t}"`);
  }
  return tokens;
}

module.exports = { parseTrustProxy };
