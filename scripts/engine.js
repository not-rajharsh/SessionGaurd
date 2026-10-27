'use strict';
// engine launcher: starts the FastAPI risk engine as a child process and waits for /health.
// Used by `npm run demo`, the e2e test, and `npm run engine` (foreground).
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ENGINE_DIR = path.join(__dirname, '..', 'risk-engine');
const VENV_PY = path.join(ENGINE_DIR, '.venv', 'bin', 'python');

function startEngine({ port, env = {}, stdio = 'inherit' }) {
  const python = fs.existsSync(VENV_PY) ? VENV_PY : 'python3';
  return spawn(
    python,
    ['-m', 'uvicorn', '--factory', 'app.main:create_app', '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'],
    { cwd: ENGINE_DIR, env: { ...process.env, ...env }, stdio },
  );
}

async function waitFor(url, timeoutMs = 20000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    try {
      if ((await fetch(url)).ok) return;
    } catch { /* not up yet */ }
    if (Date.now() > end) throw new Error(`timed out waiting for ${url}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

module.exports = { startEngine, waitFor };

if (require.main === module) {
  require('./ensure-env').ensureEnv();
  const child = startEngine({ port: process.env.ENGINE_PORT || 8000 });
  child.on('exit', (code) => process.exit(code ?? 0));
}
