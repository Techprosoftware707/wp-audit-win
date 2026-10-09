# wp-audit-win

**A self-hosted WordPress Security Audit, Vulnerability Verification, PoC
Intelligence, and Pentest Management platform.** Open-source-first, Dockerized,
and built around a hard authorization model so it is only ever pointed at
targets you are explicitly allowed to test.

> ⚠️ **Authorized use only.** Every active test is gated, server-side, by an
> authorization record for the target. This tool is for assessing systems you
> own or have written permission to test. It deliberately does **not** include
> stealth, evasion, persistence, credential theft, or any capability whose
> purpose is to compromise arbitrary third-party sites. See
> [`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/AUTHORIZATION.md`](docs/AUTHORIZATION.md).

---

## What it does

```
ADD TARGET → VERIFY AUTHORIZATION → FULL AUDIT
   → auto discovery → WP enumeration → vuln discovery
   → PoC matching (intelligence) → safe verification
   → evidence → risk score → report → retest
```

The operator adds a target, confirms authorization, and clicks **Full Audit**.
A job pipeline fans the work out to independent scanner workers, correlates
overlapping findings into single deduplicated issues, scores risk, captures
evidence, and produces a report — without the operator running individual
scanner commands by hand.

## Two operating modes

| Mode | Purpose | Aggressiveness |
|------|---------|----------------|
| **Authorized Production Testing** | Assess real, authorized targets | Safe/standard; capped by per-target intensity profile and a global ceiling |
| **Isolated Exploit Lab** | Reproduce vulnerabilities against disposable/intentionally-vulnerable instances | Aggressive, but network-isolated and auto-reset |

Lab reproduction and any active exploit verification are **operator-driven and
human-approved** — the platform never auto-downloads and auto-executes arbitrary
exploit code. The PoC component is an *intelligence and metadata* layer (see
[`docs/POC_INTELLIGENCE.md`](docs/POC_INTELLIGENCE.md)).

## Stack (all free / open-source)

Next.js · React · Tailwind · FastAPI · PostgreSQL · Redis · MinIO · Caddy ·
WPScan · Nuclei · OWASP ZAP · Nmap · WP-CLI · WhatWeb · Nikto · ffuf · Semgrep ·
Docker. (Burp Suite is supported as an **optional** operator-configured
integration — OWASP ZAP is the built-in free default for deep web testing.)

No paid SaaS, no paid scanners, no mandatory proprietary API. `WPSCAN_API_TOKEN`
and `NVD_API_KEY` are **optional** enrichment only; everything works without them.

## Architecture

```
                 Admin browser
                      │  HTTPS
              ┌───────▼────────┐
              │  Caddy (proxy) │   TLS, security headers
              └───┬────────┬───┘
         /api/*   │        │  /*
          ┌───────▼──┐  ┌──▼────────┐
          │ FastAPI  │  │ Next.js   │
          │  (api)   │  │ (frontend)│
          └──┬────┬──┘  └───────────┘
   control   │    │ control
    plane    │    └──────────────┐
      ┌──────▼─────┐   ┌──────────▼─────┐   ┌───────┐
      │ PostgreSQL │   │ Redis (queue)  │   │ MinIO │
      └────────────┘   └───────┬────────┘   └───────┘
                               │ jobs
                 ┌─────────────▼──────────────┐  scanner network
                 │ workers (wpscan/nuclei/zap/ │────► authorized targets
                 │ nmap/wpcli/general)         │────► zap engine
                 └─────────────────────────────┘
```

The **API/web tier is not on the scanner network and has no Docker socket**.
Workers bridge the control plane (queue/db) and the scanner network (egress +
ZAP engine). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quickstart

```bash
git clone <this repo> && cd wp-audit-win
sudo ./scripts/install.sh          # checks Ubuntu, installs Docker if missing,
                                    # generates secrets, starts stack, migrates,
                                    # creates the admin user, runs health checks
```

Then open the printed URL (default `https://localhost`), log in with the admin
credentials the installer generated, add a target, mark it authorized, and run
a scan.

Bring up the heavy scanners (WPScan/ZAP/WP-CLI images) when you need them:

```bash
docker compose --profile scanners up -d
```

### Run it the manual way

```bash
cp .env.example .env            # then edit secrets (or let install.sh generate)
docker compose up -d --build
docker compose exec api alembic upgrade head
docker compose exec api python -m app.cli.bootstrap   # create admin
./scripts/health-check.sh
```

### Local dev without Docker

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
WPSEC_ENV=development uvicorn app.main:app --reload   # SQLite, in-proc queue
python -m pytest -q                                   # full test suite
```

## CLI

The `wpsec` CLI talks to the REST API:

```bash
wpsec login
wpsec target add --url https://example.com --owner "Me"
wpsec target authorize <id> --type written-consent --expires 2026-12-31
wpsec scan start <id> --profile standard
wpsec scan status <scan-id>
wpsec finding list <scan-id>
wpsec report generate <scan-id> --format html
wpsec poc update                      # sync free vuln-intel sources (NVD/KEV/OSV/GHSA…)
wpsec poc collect --limit 100         # download+hash+classify PoC artifacts (never executed)
```

See [`backend/app/cli`](backend/app/cli) and `wpsec --help`.

## Repository layout

```
backend/        FastAPI app, models, migrations, workers, CLI, tests
worker/         Worker image (scanner tools layered on the backend image)
frontend/       Next.js dashboard
deploy/         Caddy reverse proxy config
scripts/        install / update / backup / restore / health-check
docs/           architecture, security, authorization, PoC intelligence
samples/        sample data for a demo environment
```

## Status

The platform is implemented and runnable end-to-end: deployment, backend core,
data model, auth/RBAC/audit, authorization gating, job engine, the 19-step
one-click Full Audit pipeline, correlation, risk, evidence, reporting, free
vulnerability intelligence (NVD/CISA-KEV/OSV/GitHub-Advisory + WPScan/
WordPress.org/vendor), the SSRF-safe PoC artifact collector, CLI, dashboard,
tests, and installer. Scanner tooling and detection data (nuclei templates,
semgrep rulesets, content wordlist) ship in the worker image for a
ready-to-run Ubuntu 24 deployment; any component that degrades gracefully when
its binary/engine is absent is marked explicitly in code and in
[`docs/STATUS.md`](docs/STATUS.md). Nothing is a silent placeholder.

**Safety boundary (by design):** this tool performs *authorized* assessment and
*operator-driven* verification. It does **not** autonomously compromise targets,
create admin accounts through exploits, steal credentials/tokens, run arbitrary
commands on third-party systems, or escalate to host root. Collected PoCs are
hashed, statically classified, and left UNVERIFIED — never auto-executed. Any
aggressive reproduction happens only in the isolated, human-approved lab. See
[`docs/SECURITY.md`](docs/SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
