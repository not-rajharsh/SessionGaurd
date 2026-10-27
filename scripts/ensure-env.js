'use strict';
// ensure-env: creates .env from .env.example with random secrets if missing, then loads it.
// Never overwrites an existing .env. Run directly or via `npm run demo`.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const ENV_PATH = path.join(ROOT, '.env');

function ensureEnv() {
  if (!fs.existsSync(ENV_PATH)) {
    const rand = (n) => crypto.randomBytes(n).toString('hex');
    const filled = fs
      .readFileSync(path.join(ROOT, '.env.example'), 'utf8')
      .replace(/^DEMO_PASSWORD=$/m, `DEMO_PASSWORD=${rand(8)}`)
      .replace(/^SESSION_SECRET=$/m, `SESSION_SECRET=${rand(32)}`)
      .replace(/^ENGINE_API_KEY=$/m, `ENGINE_API_KEY=${rand(32)}`);
    fs.writeFileSync(ENV_PATH, filled, { mode: 0o600 });
    console.log('[env] created .env with random secrets');
  }
  process.loadEnvFile(ENV_PATH);
  return ENV_PATH;
}

module.exports = { ensureEnv, ROOT };
if (require.main === module) ensureEnv();
