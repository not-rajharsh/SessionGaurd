# session-guard — Phase 1: core detection

Demo bank app (Express + Redis sessions) protected by a FastAPI risk engine (layer a only).
Everything here targets the local demo app only.

## Run
    redis-server                 # or: docker run -p 6379:6379 redis:7
    npm run setup                # venv + pip + npm + Playwright Chromium
    npm run demo                 # legit session allowed, replayed session blocked, signals printed
    npm test                     # 25 pytest + 9 node tests (Redis optional; its test skips if down)

`npm run demo` creates `.env` with random secrets on first run (never overwrites one).
Log in manually at http://127.0.0.1:3000 with `DEMO_USER` / `DEMO_PASSWORD` from `.env` (`npm run engine` + `npm run app`).
No Chromium download access? Set `PW_CHROMIUM_PATH` to an existing binary.

## Layout
- `demo-app/`     Express app, `riskGuard.js` middleware (integration = 3 lines), tests
- `risk-engine/`  FastAPI `/evaluate`, checks, scoring, Redis/memory store, SQLite event log, tests
- `attack/`       Playwright cookie-replay script
- `scripts/`      `demo.js` orchestrator, engine launcher, `.env` bootstrap

## Phase 1 behaviour worth knowing
- Baseline = first `/evaluate` call for a session id (the app makes it right after login).
- `last_seen` (for impossible travel) only advances on ALLOWED requests; a terminated session stays terminated.
- Score = capped sum of signal weights (ip 10, asn 20, UA 30, fingerprint 35, travel 40). <30 allow, 30–70 challenge (403), >70 terminate (401).
- Geo/ASN comes from a small offline demo table (`risk-engine/app/data/geo_demo.json`); swap `GeoDB.lookup` for GeoLite2 later.
- Fingerprint is a passive header hash for now; the client agent replaces it in a later phase.
- Demo-only: `TRUST_PROXY=true` (spoofable X-Forwarded-For) and `EXPOSE_SIGNALS=true`.
