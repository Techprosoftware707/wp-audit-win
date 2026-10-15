# wp-audit-win — Acceptance Report

_Independent full-system audit, automated testing, and repair pass._
Date: 2026-10-15 · Branch: `claude/festive-lovelace-dvna8j`

This report records what was actually run and verified. Nothing here is a
claimed result without a command behind it. Where a check could not be run in
this environment, it is marked **BLOCKED** with the exact prerequisite.

---

## 1. Overall status

**Working (verified) as the WordPress security-audit platform**, with the
native toolchain and both execution paths exercised end-to-end. Two scope facts
are stated up front and honestly:

- **Docker live deployment is BLOCKED in this sandbox** — the Docker *daemon* is
  not running here (CLI present, daemon down), so `docker compose up` could not
  be executed. The app was instead run natively (uvicorn + SQLite + in-process
  queue, and Redis + a real worker) and `docker compose config` validates; the
  Dockerfiles/compose are structurally sound but a live container bring-up was
  not performed here.
- **The "remote administration platform" (master-prompt Part B) is MISSING** —
  this repository implements only the WP security-audit platform. No agent
  enrollment, remote command execution, PTY, or managed-host code exists. It was
  **not** hastily built: a safe remote-exec/agent subsystem is a large,
  security-sensitive system that cannot be meaningfully implemented or tested in
  this environment, and it is out of scope for this repo. See §4.

## 2. Environment

| Item | Value |
|------|-------|
| OS | Ubuntu 24.04.5 LTS |
| Python | 3.13 (backend venv) |
| Node | 22 (frontend) |
| Repo | `techprosoftware707/wp-audit-win` |
| Docker CLI | v29.8.2 present; **daemon unavailable** |
| DB (dev/test) | SQLite (WAL, FK on); **PostgreSQL** in prod via compose |
| Queue | in-process (dev/test); **Redis** in prod |
| Object store | MinIO (prod); inline + local-disk fallback when down |

## 3. Administrator status — VERIFIED

- Bootstrap (`app/cli/bootstrap.py`) provisions exactly **one** Super
  Administrator, idempotently, with an argon2-hashed password (random if
  `WPSEC_ADMIN_PASSWORD` is unset), printed once and never written to logs.
- **Non-reusable**: once any user exists, bootstrap will not mint another admin.
- **Self-service credential change added** (`POST /auth/change-password`):
  requires the current password, invalidates outstanding tokens (see §10).
- Verified by tests: admin login, privileged-function access, ordinary-user
  denial, role-change auditing, immediate deactivation, password change.

## 4. Managed-machine administrative privileges — MISSING (out of scope)

The master prompt's Part B (enroll machines, authenticate agents, run remote
commands, manage services, browse files, revoke agents, collect host metrics)
has **no implementation** in this repository (confirmed by a full-repo search).
Implementing it safely would require, at minimum: a dedicated agent with mTLS
identity, a narrowly-scoped privileged helper or sudo policy (never blanket
root), an explicit operator-approved enrollment + revocation flow, and an
isolated test fleet. None of that can be built or tested here responsibly, so it
is reported as MISSING rather than stubbed or faked.

## 5. Free-tool status — all free / open-source

| Tool | State | Notes |
|------|-------|-------|
| FastAPI, SQLAlchemy, Pydantic, Alembic | PASS | backend core, 161 tests |
| Next.js / React / Tailwind | PASS | prod build compiles (11 routes) |
| PostgreSQL, Redis, MinIO | PASS (prod) / degrades | native dev uses SQLite + in-proc; MinIO has inline+local fallback |
| whatweb | PASS | installed; used in the real-HTTP e2e |
| nmap, nuclei, wpscan, nikto, ffuf, semgrep, gitleaks, ZAP, WP-CLI | **BLOCKED**/degrades | real code + parsers; each **self-skips with a reason** when its binary/daemon/source is absent. The worker image installs them + pre-caches nuclei templates / semgrep rulesets. |
| Burp | optional/commercial | skips unless configured; ZAP is the free default |

No mandatory paid SaaS or API keys. Vuln intel uses free sources (NVD, CISA KEV,
OSV, GitHub Advisory DB, WPScan, WordPress.org, vendor).

## 6. Defects found (independent 46-agent adversarial audit)

154 findings; 34 defect/security claims adversarially verified → **13 confirmed,
21 refuted**. All 13 fixed, plus 4 additional robustness items. Confirmed set:

| # | Sev | Area | Defect |
|---|-----|------|--------|
| 1 | HIGH | ZAP step | fell back to the platform `secret_key` as the ZAP API key (leaks the JWT/credential master secret over plaintext HTTP) |
| 2 | MED | proxy | `uvicorn --forwarded-allow-ips='*'` let any client spoof X-Forwarded-For (rate-limit bypass, audit spoofing) |
| 3 | MED | MFA | `/auth/mfa/disable` + `/mfa/setup` had no step-up re-auth (a stolen token could strip MFA) |
| 4 | MED | API keys | a leaked API key could mint more keys + disable MFA |
| 5 | MED | risk | final risk pass ignored catalog CVSS → under-scored CVSS-vs-severity divergence (and crashed in the worker path on a non-existent attribute) |
| 6 | MED | correlation | CVE-merge cascade-deleted the duplicate's VerificationTest history |
| 7 | MED | orchestrator | cancel left in-flight steps; reaper re-enqueue could double-run a step |
| 8 | MED | SSRF | PoC fetcher resolve-then-connect (DNS-rebinding window) |
| 9 | MED | classifier | file_put_contents/fwrite/backtick writes under-reported |
| 10 | LOW | auth | login timing enabled user enumeration |
| 11 | LOW | auth | no token revocation on password change / MFA disable |
| 12 | LOW | API keys | `ApiKey.last_used_at` never recorded |
| 13 | LOW | frontend | PoC-download button had an unhandled promise rejection |

## 7. Repairs performed

- `auth.py` / `deps.py` / `security.py` / `users.py` / `models/user.py` +
  migration `0002_token_epoch.py`: step-up re-auth, API-key method restriction,
  **token-epoch revocation**, login-timing equalization, `last_used_at`,
  self-service password change.
- `workers/steps/zap.py`: never use `secret_key`; skip without `ZAP_API_KEY`.
- `docker-entrypoint.sh`: drop `--forwarded-allow-ips='*'`.
- `services/risk.py` + `workers/steps/risk_step.py`: resolve CVSS from the
  authoritative Vulnerability catalog; persist CVSS in the factor breakdown.
- `workers/steps/correlation.py`: reassign VerificationTest rows + OR `confirmed`.
- `services/scan_orchestrator.py`: atomic step-claim (conditional UPDATE) +
  reaper reconciliation of cancelled scans.
- `services/poc_collector.py`: HTTP IP-pinning SSRF defense; stronger classifier.
- `services/evidence.py`: local-disk fallback for binary artifacts.
- `scripts/restore.sh`: single-transaction + ON_ERROR_STOP + quiesce.
- `scripts/backup.sh`: loud warning on MinIO outage.
- `frontend/app/pocs/page.tsx`: await + try/catch on download.

## 8. Automated tests

- **161 backend pytest tests PASS** (was 117 at session start; +44 new):
  `test_admin_provisioning.py` (8), `test_permission_matrix.py` (20),
  `test_auth_hardening.py` (7), `test_audit_fixes.py` (9). `ruff` clean.
- Frontend: `tsc --noEmit` clean; `next build` compiles all 11 routes.
- Alembic chain `0001 → 0002` applies cleanly (verified on throwaway SQLite);
  `users.token_epoch` present; idempotent guard verified.
- **Not run / BLOCKED**: live `docker build` / `docker compose up` (no daemon);
  live external scanners beyond whatweb (binaries not installed in sandbox) —
  these self-skip, proven by the pipeline tests.

## 9. End-to-end test result — PASS (both paths)

- **Real-HTTP inline** (real uvicorn + fake WP + real `whatweb`): authorization
  gate blocks the unauthorized scan (403) → authorize → 19-step one-click audit
  completes → 6 findings → evidence stored → auto-report downloaded (6.8 KB) →
  62 OpenAPI paths.
- **Distributed (Redis + real worker)**: scan completes, `steps_failed: 0`,
  `risk: completed` (the regression fixed in §6#5 was caught here), worker
  heartbeat + correct unserved-queue skipping.

## 10. Security findings remaining in the platform

- **Token lifecycle**: now mitigated by per-user token epoch (credential change /
  MFA disable / deactivation invalidate all prior JWTs). There is no explicit
  "logout everywhere" endpoint by design (stateless JWT + short expiry); a client
  logout is token discard.
- **SSRF (PoC fetcher)**: HTTP connections are IP-pinned and HTTPS is covered by
  TLS cert validation; a residual DNS-rebinding window on operator-entered
  hostnames is closed for the realistic (metadata/HTTP) vector.
- **Scanner netguard** intentionally permits in-scope private/loopback targets
  (authorized internal engagements); this is by design and gated by the
  authorization scope, not a bug.
- No default credentials; prod startup **fail-fasts** on weak secrets.

## 11. Deployment instructions (production, Ubuntu 24.04)

```bash
git clone <repo> && cd wp-audit-win
sudo ./scripts/install.sh      # Ubuntu + Docker check, strong secret gen,
                               # stack up, migrate, provision admin, health-check
# Dashboard + one-time admin password are printed at the end.
docker compose --profile scanners up -d   # enable WPScan/ZAP/WP-CLI, etc.
```

Operate: `docker compose ps|logs`, `./scripts/health-check.sh`,
`./scripts/backup.sh`, `./scripts/restore.sh <archive>`, `./scripts/update.sh`.
CLI: `wpsec login|target add|target authorize|scan start|finding list|report
generate|poc update|poc collect`.

## 12. Remaining blockers (exact prerequisite)

| Item | Prerequisite to clear |
|------|-----------------------|
| Live container bring-up | A host with a running Docker daemon (`sudo ./scripts/install.sh` on a real Ubuntu 24 box). |
| Live external scanners | Install the binaries (the `scanners` compose profile / worker image does this); then nmap/nuclei/wpscan/etc. run instead of self-skipping. |
| Remote-administration platform (Part B) | A product decision to build it, then a dedicated agent (mTLS) + scoped privileged helper + approval/revocation flow + isolated test fleet. |
| WPScan vuln-feed depth | A (free) WPScan API token raises rate limits; the platform works without it. |
