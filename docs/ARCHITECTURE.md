# Architecture

## Components

| Service | Role | Network |
|---------|------|---------|
| `reverse-proxy` (Caddy) | TLS termination, security headers, routes `/api/*`→api, `/*`→frontend | control |
| `frontend` (Next.js) | Operator dashboard (SPA, token auth) | control |
| `api` (FastAPI) | REST API, auth/RBAC, orchestration, reporting | control |
| `postgres` | System of record (28 tables) | control |
| `redis` | Job queue + rate limiting | control |
| `minio` | Evidence & report object storage | control |
| `worker` (general) | Runs fingerprint/nmap/nuclei/correlation/poc/report steps | control + scanner |
| `worker-wpscan/zap/wpcli` | Tool-specialized workers (profile `scanners`) | control + scanner |
| `zap` | OWASP ZAP daemon (engine the zap worker drives) | scanner only |

### Network isolation

Two Docker networks:

- **control** — api, frontend, proxy, postgres, redis, minio.
- **scanner** — workers + the ZAP engine, plus egress to authorized targets.

The **API/web tier is only on the control network** and has **no Docker
socket** mounted. Workers bridge both networks: they read jobs/DB on control and
reach targets + ZAP on scanner. Scanner workers run with `cap_drop: ALL` and
`no-new-privileges`. This matches the brief's requirement to separate the
control plane from scanner workers and to keep the Docker socket away from the
web app.

## Request → scan flow

```
Operator → Caddy → FastAPI
  POST /targets/{id}/scan
      │
      ├─ authorization.assert_scannable()  ← hard gate (403 if not authorized)
      ├─ orchestrator.start_scan()
      │     ├─ clamp intensity (profile ∧ target.max ∧ auth.max ∧ global ceiling)
      │     ├─ create Scan + ScanStep rows (the DAG)
      │     └─ enqueue ready steps  → Redis queues
      │                                   │
      │                              workers dequeue
      │                                   ├─ run step (StepContext)
      │                                   ├─ persist assets/findings/evidence
      │                                   └─ advance() → enqueue next ready steps
      └─ (dev/test) execute inline synchronously
```

Steps form a dependency DAG (`DEFAULT_PIPELINE` in
`app/services/scan_orchestrator.py`). A step whose queue has no live worker is
**skipped** (recorded with a reason) rather than hanging the scan; a step whose
tool is missing self-skips. Correlation, PoC-intelligence matching, and the
final risk pass run as terminal steps.

## Execution model

The **same step runner** powers both paths:

- **Distributed** (production): Redis queues + worker processes with heartbeats.
- **In-process** (dev/test): `execute_scan_inline()` runs the DAG synchronously.
  This keeps tests hermetic (SQLite + in-memory queue + mocked HTTP) and gives a
  zero-dependency local dev loop.

## Data model

28 tables (see `app/models`). Highlights:

- `targets` ↔ `authorizations` (1-to-many, authorization is first-class)
- `scans` ↔ `scan_steps` (the DAG), `findings` ↔ `evidence` / `verification_tests`
- `vulnerabilities` (intelligence catalog) and `pocs` / `poc_sources`
  (PoC intelligence) are target-independent
- `credentials` store secrets **encrypted at rest** (Fernet)
- `audit_logs` is append-only (no update/delete API path)

## Technology choices

All free/open-source. No paid API is required to operate the base system;
`WPSCAN_API_TOKEN` and `NVD_API_KEY` are optional enrichment only.
