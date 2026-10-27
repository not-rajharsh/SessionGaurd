# session-guard — Phase 2

Demo bank app (Express + Redis sessions) protected by a FastAPI risk engine, a device-bound browser
key, passkey step-up, async LLM rationales and an admin dashboard. Everything here targets the local
demo app only.

## Run
    redis-server                  # or: docker run -p 6379:6379 redis:7
    npm run setup                 # venv + pip + npm + Playwright Chromium
    npm run demo                  # 3 scenarios + summary (creates/upgrades .env, registers the demo passkey)
    npm test                      # pytest + node tests + browser tests (Chromium)

No Chromium download access? `export PW_CHROMIUM_PATH=/path/to/chromium`.
Dashboard: run `npm run engine` and `npm run app`, open http://localhost:3000/admin
(`ADMIN_USER` / `ADMIN_PASSWORD` in `.env`). Demo user: `DEMO_USER` / `DEMO_PASSWORD`.
Other scripts: `npm run register-passkey [-- --force]`, `npm run netsim`.

## Layers, and what each one does NOT protect against

| Layer | What it does | Does NOT protect against |
|---|---|---|
| **1. Deterministic checks** (IP, ASN, UA, header fingerprint, impossible travel) | Catches a replay from a different place or client. | An attacker who copies the victim's UA, headers and IP (the *adaptive attacker*: score 0, allowed; kept as a test, `layer1_gap`). The header fingerprint is a **weak** signal (weight 10): headers are copyable. Geo data is a tiny demo table. |
| **2. Device-bound key** (non-extractable WebCrypto key, single-use 30 s nonces, per-action proofs) | A stolen cookie without the key cannot do `/transfer` (needs its own proof) or read after the 30 s presence window. The key cannot be copied out of the browser. | **Malware or XSS running on the victim's own device/origin can still *use* the key** (ask it to sign): it just can't copy it. Reads inside the 30 s window after a legitimate presence proof are not stopped by layer 2. Login-time compromise (attacker has the password and logs in with their own key). Real-time phishing relays during login. A compromised server, engine or Redis. |
| **3. Passkey step-up** (WebAuthn via SimpleWebAuthn) | A "challenge" verdict needs a real passkey assertion; success grants 5 min of elevated trust, failure or a 60 s timeout terminates. | An attacker who also controls the victim's authenticator. The elevated window suppresses *challenge* verdicts (never *terminate*) for 5 minutes. The timeout is enforced at the next request, not by a timer. Demo passkeys live in a **virtual** authenticator, not hardware. |
| **4. LLM rationale** | Writes a paragraph for analysts, async, after the decision. | It protects nothing: it can never change the action. Treat its text as untrusted (it is escaped, truncated, and has a template fallback). |
| **5. Dashboard** | Session list, score timeline, signals, rationale. | Hardening of the admin login itself: single password, no rate limit, no MFA (demo-grade). |

Also out of scope: behavioral biometrics / model training (Phase 3), CSRF tokens beyond SameSite=Lax,
and the demo's JSON passkey store (use a database in production).

## How it fits together
- **Fusion** (`risk-engine/app/scoring.py`): clamped sum. IP +10, ASN +20, UA +30, fingerprint +10, travel +40;
  `proof_valid` **-25**; `proof_stale` +35, `proof_missing` +50, `proof_expired` +50 (step-up);
  `proof_invalid` +80 (terminate). <30 allow, 30-70 challenge, >70 terminate.
- **Binding:** the login form generates the key *before* submitting and sends only the public key, so the
  session is born bound. The engine's `/bind` is service-only, atomic and refuses any rebind; a new key
  needs a new full login (new session id).
- **Proofs:** signature over `"<nonce>|<purpose>"`, purpose = `presence` or `METHOD path`, nonce single use.
- **Unbound sessions** (`REQUIRE_DEVICE_KEY=false`, non-browser tooling) behave exactly like Phase 1.
- **Events** live in SQLite, keyed by a short hash of the session id (the id itself is a bearer token and is
  never stored or shown). Live state is in Redis.

## Configuration (`.env`, see `.env.example`)
- `TRUST_PROXY` (default **blank = trust nobody**): `X-Forwarded-For` is read only when the TCP peer is in
  this list of proxy IPs/CIDRs, and then only the right-most untrusted hop is used. Hop counts are rejected;
  `true` is mapped to `loopback` with a warning. `npm run demo` sets `loopback` for its edge simulator
  (`scripts/netsim.js`), which stands in for a real proxy so one machine can fake different locations.
- `EXPOSE_SIGNALS=true` is demo-only; set `false` in production.
- `LLM_PROVIDER=none|openai|anthropic`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_TIMEOUT_SECONDS`.
  `openai` means any OpenAI-compatible `/chat/completions` endpoint. With `none`, or on any error/timeout,
  a deterministic template is used. User-agent and other request strings reach the model only as sanitized
  `untrusted_data` fields of a JSON payload.
- Tunables: `PROOF_MAX_AGE_SECONDS` (30), `NONCE_TTL_SECONDS` (30), `ELEVATED_SECONDS` (300),
  `STEPUP_TIMEOUT_SECONDS` (60).
- WebAuthn needs `localhost` or HTTPS; origins default to `http://localhost:$APP_PORT`.

## Notes on Phase 1 tests
All Phase 1 tests still pass. Two test *settings* changed because the defaults became secure: the Phase 1
non-browser e2e test now sets `REQUIRE_DEVICE_KEY=false` (its curl-style login has no device key), and it
keeps `TRUST_PROXY=true`, which is now interpreted as `loopback`. The fingerprint weight changed (35 -> 10);
no Phase 1 assertion depended on it.
