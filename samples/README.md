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

> Only ever point the scanner at hosts you own or are authorized to test. The
> platform enforces this with the authorization gate; this compose file gives
> you a target you indisputably own.
