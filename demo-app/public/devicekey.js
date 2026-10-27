// devicekey.js: the browser half of the device-bound key (layer 2).
// B1: generates an ECDSA P-256 key with extractable:false, keeps only the key HANDLE in
//     IndexedDB (the private bytes are not readable by any script, including ours), and
//     exposes just the PUBLIC key. Malware running in this browser can still ask the key to
//     SIGN, it just can't copy it elsewhere.
// B3: proof = signature over "<nonce>|<purpose>" ("presence" or "<METHOD> <path>").
window.SG = window.SG || {};
(() => {
  const DB = 'sg-device', STORE = 'keys', KEY = 'device';
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const openDb = () => new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  const idb = async (mode, fn) => {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  };

  // Called by the login form BEFORE submitting: the session is born bound to this key.
  SG.generate = async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await idb('readwrite', (s) => s.put(pair.privateKey, KEY)); // structured clone of a non-extractable key
    return b64(await crypto.subtle.exportKey('spki', pair.publicKey));
  };

  const sign = async (message) => {
    const key = await idb('readonly', (s) => s.get(KEY));
    if (!key) throw new Error('no device key in this browser');
    return b64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(message)));
  };

  const proofHeader = async (purpose) => {
    const r = await fetch('/auth/challenge', { method: 'POST' });
    if (!r.ok) throw new Error(`challenge failed: ${r.status}`);
    const { nonce } = await r.json();
    return `${nonce}.${await sign(`${nonce}|${purpose}`)}`;
  };

  // Every state-changing request carries its own single-use proof for exactly that action.
  SG.fetchWithProof = async (path, init = {}) => {
    const method = (init.method || 'GET').toUpperCase();
    const proof = await proofHeader(`${method} ${path}`);
    return fetch(path, { ...init, headers: { ...(init.headers || {}), 'X-Device-Proof': proof } });
  };

  // Presence heartbeat: keeps the 30 s freshness window alive while the page is open.
  SG.presence = async () => {
    const proof = await proofHeader('presence');
    return fetch('/auth/presence', { method: 'POST', headers: { 'X-Device-Proof': proof } });
  };
  SG.startHeartbeat = (ms = 15000) => {
    SG.presence().catch(() => {});
    return setInterval(() => SG.presence().catch(() => {}), ms);
  };
})();
