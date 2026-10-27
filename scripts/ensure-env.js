'use strict';
// ensure-env: creates .env from .env.example (random secrets) if missing; if it exists, APPENDS any
// keys it lacks (so Phase 1 users get the new settings) and migrates the unsafe TRUST_PROXY=true.
// Never overwrites values you set. Then loads it. Run directly or via `npm run demo`.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const ENV_PATH = path.join(ROOT, '.env');
const SECRET_BYTES = { DEMO_PASSWORD: 8, ADMIN_PASSWORD: 12, SESSION_SECRET: 32, ENGINE_API_KEY: 32 };

const fillLine = (line) => {
  const m = /^([A-Z_]+)=(.*)$/.exec(line);
  return m && SECRET_BYTES[m[1]] && !m[2] ? `${m[1]}=${crypto.randomBytes(SECRET_BYTES[m[1]]).toString('hex')}` : line;
};

function ensureEnv() {
  const example = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8').split('\n');
  if (!fs.existsSync(ENV_PATH)) {
    fs.writeFileSync(ENV_PATH, example.map(fillLine).join('\n'), { mode: 0o600 });
    console.log('[env] created .env with random secrets');
  } else {
    let cur = fs.readFileSync(ENV_PATH, 'utf8');
    const have = new Set([...cur.matchAll(/^([A-Z_]+)=/gm)].map((m) => m[1]));
    const add = example.filter((l) => /^[A-Z_]+=/.test(l) && !have.has(l.split('=')[0])).map(fillLine);
    if (add.length) {
      cur = `${cur.replace(/\n*$/, '\n')}\n# added by Phase 2 upgrade\n${add.join('\n')}\n`;
      console.log(`[env] added ${add.length} new setting(s) to .env: ${add.map((l) => l.split('=')[0]).join(', ')}`);
    }
    if (/^TRUST_PROXY=true\s*$/m.test(cur)) {
      cur = cur.replace(/^TRUST_PROXY=true\s*$/m, 'TRUST_PROXY=');
      console.log('[env] TRUST_PROXY=true is unsafe (trusts every sender); reset to blank');
    }
    fs.writeFileSync(ENV_PATH, cur, { mode: 0o600 });
    fs.chmodSync(ENV_PATH, 0o600); // `mode` above only applies to newly created files; .env holds secrets
  }
  process.loadEnvFile(ENV_PATH);
  return ENV_PATH;
}

module.exports = { ensureEnv, ROOT };
if (require.main === module) ensureEnv();
