# Sample data & integration targets

## Seed demo data

Populate a fresh install with an example authorized target, sample catalog
vulnerabilities, and a lab template:

```bash
docker compose exec api python -m app.cli.seed_demo
# or locally:  cd backend && python -m app.cli.seed_demo
```

The demo target uses the non-routable host `demo.wpsec.local`, so it is safe to
keep around while exploring the dashboard. (It won't return scan findings unless
you point that hostname at a WordPress instance you control.)

## Deliberately-vulnerable integration target

For end-to-end testing against a *real* but disposable WordPress, stand up an
intentionally old WordPress + plugin on an isolated network and authorize it.
`docker-compose.labtarget.yml` here brings up such a target (WordPress + MySQL)
you fully control:

```bash
docker compose -f samples/docker-compose.labtarget.yml up -d
# then in wp-audit-win: add target http://localhost:8081, authorize it (scope
# 127.0.0.1 / localhost), and run a Full Audit.
```

The lab mounts an **inert, lab-gated detection fixture**
(`lab-fixtures/wp-audit-lab-fixtures.php`) as an mu-plugin. It exposes one
intentionally-public REST route (`/wp-json/wp-audit-lab/v1/open-endpoint`) with
**no capability check** — a detectable "missing authorization" pattern — but the
handler returns only a harmless marker (no data, no state change, no user
creation). It loads only when `WPAWC_LAB` is defined, so it can never run on a
real site. Combined with the intentionally-outdated WordPress image, the lab
exercises both version-based and configuration findings while staying inert.

> Only ever point the scanner at hosts you own or are authorized to test. The
> platform enforces this with the authorization gate; this compose file gives
> you a target you indisputably own.

## Sample report (vulnerable → validated → fixed → retested)

`sample-report.html` / `sample-report.json` are a REAL report produced by the
scan pipeline (not hand-written), regenerated any time with:

```bash
# from the repo root, with the backend venv:
./backend/.venv/bin/python - <<'PY'
# (see the generator used in CI/dev; it runs a Full Audit against the mock WP)
PY
```

The sample shows five confirmed findings (plaintext HTTP, REST user
enumeration, missing security headers, XML-RPC exposed, version disclosure),
each with severity, evidence, and `verification_status: confirmed`.

**Before → after narrative** (run end-to-end in the lab above):

1. **Detect** — Full Audit flags an outdated plugin by version and the open
   `/wp-audit-lab/v1/open-endpoint` (missing capability check).
2. **Validate** — the finding's safe verification (`endpoint_presence`, a benign
   GET) confirms the endpoint is reachable without auth; evidence is stored.
3. **Fix** — approve remediation: `wpsec recovery update <target> plugin <slug>
   --reason "patch CVE" --confirm` updates the plugin (backup first; never
   downgrades).
4. **Retest** — rescan; the version-based finding clears and the before/after
   report shows the delta.
