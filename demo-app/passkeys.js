'use strict';
// passkeys: tiny JSON-file store for registered WebAuthn credentials (demo-grade; use a DB in
// production). Holds PUBLIC data only: credential id, public key, signature counter.
// Re-read on every call so the setup script and the running app stay in sync.
const fs = require('node:fs');
const path = require('node:path');

function createPasskeyStore(file) {
  const read = () => {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
  };
  const write = (data) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file); // atomic replace
  };
  return {
    file,
    get: (user) => read()[user] || null,
    set: (user, cred) => write({ ...read(), [user]: cred }),
    update: (user, patch) => { const d = read(); if (d[user]) write({ ...d, [user]: { ...d[user], ...patch } }); },
  };
}

module.exports = { createPasskeyStore };
