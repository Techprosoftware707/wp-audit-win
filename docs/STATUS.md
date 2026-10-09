# Implementation status

Honest inventory of what is fully implemented, what degrades gracefully, and
what is an explicit extension point. Nothing in the codebase is a silent
placeholder.

## Fully implemented & tested

- Deployment: `docker-compose` (control + scanner networks), Caddy TLS proxy,
  installer/update/backup/restore/health-check scripts.
- Backend core: config, SQLAlchemy models (28 tables) for every required entity,
  Alembic migration, argon2 + JWT + TOTP, Fernet credential encryption, RBAC,
  append-only audit, Redis/in-process job queue.
- REST API (58 paths) with OpenAPI docs; `wpsec` CLI.
- **Authorization gate** enforced server-side (unit-tested): time window + scope
  + status, with intensity clamping. A run-time re-check failure **aborts** the
  scan before any scanner runs.
- Scan orchestration (DAG executor, 19-step one-click pipeline), worker runtime
  with heartbeats, a **scheduler** that fires due schedules, and a **reaper** that
  self-heals stuck/lost jobs. Identical inline (dev/test) and distributed
  (Redis + worker) execution — both verified end-to-end over real HTTP against a
  live target with the real `whatweb` binary.
- Steps (always run in the base stack): `authorization`, `discovery`,
  `wp_fingerprint` (dependency-free, real), `correlation`, `poc_match`,
  `change_detect` (diffs inventory vs the previous scan into `change_events`),
  `risk`, `auto_report`.
- Finding correlation/dedup (unique `(target,dedup_key)` + merge-on-conflict),
  CVSS-aware risk engine, evidence engine (MinIO with bounded-timeout +
  negative-cache fallback to inline), reporting (HTML/JSON/CSV/Markdown with
  autoescaping; PDF via optional weasyprint).
- Verification engine: `version_match`, `endpoint_presence`, `info_exposure`
  fully functional and scope-confined; active methods approval-gated.
- Vulnerability intelligence: catalog + matching + collectors for **NVD, CISA
  KEV, OSV, and the GitHub Advisory Database**, plus registered **WPScan /
  WordPress.org / vendor** sources. Background sync via the worker maintenance
  loop; KEV is distinguished from merely-published.
- Next.js dashboard: login, dashboard, targets (+add, authorize, one-click Full
  Audit), **scan detail (live stages + Stop + JSON/CSV/HTML export, failed stages
  surfaced)**, **finding detail (evidence, CVE link, remediation, safe
  verification, status/retest workflow)**, findings (filters), PoC library,
  workers.
- Security hardening from the audit: SSRF/scope guard on all target HTTP (manual
  redirect validation), X-Forwarded-For trusted only from configured proxies,
  per-account + per-IP login throttling, no-shell subprocesses (WP-CLI path
  quoted), SSH host-key verification by default, secret redaction (incl. Gitleaks),
  commit-before-enqueue job durability.
- Test suite: 96 pytest tests (hermetic: SQLite + in-process queue + mocked HTTP)
  plus two end-to-end harnesses (real-HTTP inline, and Redis + worker distributed).

## Degrades gracefully (works when the tool/engine is present)

These steps **skip with a recorded reason** when their binary/engine/config is
not available, so the base stack always completes a scan. Install them via the
`scanners` compose profile (the worker image bundles the tools):

- `nmap`, `nuclei`, `wpscan`, `whatweb`, `nikto`, `ffuf` — need their binaries
  (the worker image installs each resiliently; a failed install self-skips).
- `zap` — needs the ZAP daemon (the `zap` service, `scanners` profile).
- `semgrep` / `gitleaks` — static source analysis; need the binary **and** a
  source tree (`WPSEC_SOURCE_DIR`). Gitleaks redacts any secret it finds.
- `wpcli` — needs an SSH credential on the target **and** `paramiko`.
- `burp` — **optional, commercial**: skips unless `BURP_API_URL` is set. OWASP
  ZAP is the built-in free default for deep web testing.

The one-click **Full Audit** runs all of the above automatically and ends with an
`auto_report` step that generates a downloadable report. Every step runs only
after the authorization gate passes.

## Explicit extension points (architected, opt-in)

- **Lab `docker` provider** — the `record` provider is the default and fully
  wired; launching real disposable WordPress containers runs on the lab worker
  and is opt-in (see [LAB.md](LAB.md)). This is where aggressive exploit
  reproduction belongs — operator-driven, isolated, never against live targets.
- **Cron-precise schedules** — interval presets (hourly/6h/daily/weekly/monthly)
  fire exactly; a raw cron string is currently advanced hourly (a full cron
  parser is an optional dependency).
- **Credential-key rotation helper** — re-encrypt existing ciphertext after
  rotating `WPSEC_CREDENTIAL_KEY`.
- **Prometheus/Grafana/Loki** — worker/API health is exposed in the DB and API;
  wiring an exporter + dashboards is a documented add-on.
- **Extra dashboard pages** — Evidence/Credentials/Schedules/Lab/Audit/Settings
  are fully served by the REST API + `wpsec` CLI; dedicated UI pages beyond the
  core workflow are thin wrappers to add on top.

## Build/run environment note

Validated with the native toolchain: 96 backend tests, end-to-end over real HTTP
(inline **and** Redis + worker distributed, using the real `whatweb` binary), and
`docker compose config` for all profiles. Live `docker build` / `docker compose
up` were not exercised in the authoring sandbox (no Docker daemon); the
Dockerfiles/compose are structurally valid and install the same pinned
dependencies verified in the venv/npm builds.

## Not built (by design)

Autonomous compromise of real targets, exploit-created admin accounts, credential/
session theft, automatic privilege escalation to host root, stealth, evasion,
persistence, destructive payloads, and any unrestricted "scan arbitrary site"
path. Aggressive exploit reproduction is confined to the isolated lab and is
operator-approved. See [SECURITY.md](SECURITY.md) and [VERIFICATION.md](VERIFICATION.md).
