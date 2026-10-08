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
  + status, with intensity clamping.
- Scan orchestration (DAG executor), worker runtime with heartbeats.
- Steps: `authorization`, `discovery`, `wp_fingerprint` (dependency-free, real),
  `correlation`, `poc_match`, `risk` — all run in the base stack.
- Finding correlation/dedup, CVSS-aware risk engine, evidence engine
  (MinIO + inline fallback), reporting (HTML/JSON/CSV/Markdown; PDF via optional
  weasyprint).
- Verification engine: `version_match`, `endpoint_presence`, `info_exposure`
  fully functional; active methods gated by approval.
- PoC/vulnerability intelligence: catalog, matching, and the CISA-KEV + NVD
  collector.
- Next.js dashboard: login, dashboard, targets (+add), target detail (authorize,
  Full Audit, findings, inventory, report), scans, findings, PoC library,
  workers.
- 36-test pytest suite (hermetic: SQLite + in-process queue + mocked HTTP).

## Degrades gracefully (works when the tool/engine is present)

These steps **skip with a recorded reason** when their binary/engine is not
available, so the base stack always completes a scan. Install them via the
`scanners` compose profile (the worker image bundles the tools):

- `nmap` — needs the `nmap` binary.
- `nuclei` — needs the `nuclei` binary (worker image fetches it).
- `wpscan` — needs the `wpscan` gem; works without an API token.
- `zap` — needs the ZAP daemon (the `zap` service, `scanners` profile).
- `wpcli` — needs an SSH credential on the target **and** `paramiko` on the
  worker; otherwise it skips.

## Explicit extension points (architected, opt-in)

- **Lab `docker` provider** — the `record` provider is the default and fully
  wired; launching real disposable WordPress containers runs on the lab worker
  and is opt-in (see [LAB.md](LAB.md)).
- **Scheduler daemon** — schedules are stored with `next_run_at`; a periodic
  runner that fires due scans is a small cron-style loop to add next.
- **Credential-key rotation helper** — re-encrypt existing ciphertext after
  rotating `WPSEC_CREDENTIAL_KEY`.
- **Prometheus/Grafana/Loki** — worker/API metrics are exposed in the DB and API;
  wiring a metrics exporter + dashboards is a documented add-on.

## Not built (by design)

Stealth, evasion, persistence, credential theft, destructive payloads, and any
unrestricted "scan arbitrary site" path. See [SECURITY.md](SECURITY.md).
