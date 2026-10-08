# Isolated exploit lab

The lab is a separate, network-isolated environment for reproducing
vulnerabilities aggressively against **disposable** WordPress installs — never
against production targets.

## Model

- `Lab` — a template (WP version, plugin/theme + versions, PHP version), TTL,
  and auto-destroy flag.
- `LabInstance` — a disposable instance with a lifecycle:
  `pending → provisioning → running → stopped → destroyed` (`failed` on error).

## Providers

Provisioning is pluggable (`app/services/lab.py`):

- **`record`** (default) — tracks instance lifecycle without launching
  containers. Safe everywhere, including on hosts where the API tier
  intentionally has no Docker access. Used for planning and to drive the
  verification/matching workflow.
- **`docker`** — launches a disposable WordPress container on the isolated
  `wpsec-lab` network via the **lab worker** (not the API, which has no Docker
  socket). This is the extension point for full auto-reproduction: pull the
  matching WP core + plugin/theme, stand it up, run the operator-approved
  verification, collect evidence, then destroy/reset.

> The `docker` provider is intentionally **opt-in** and runs only on the lab
> worker with explicit operator action. The base system is fully functional with
> the `record` provider; see [STATUS.md](STATUS.md) for what is wired vs.
> extension-point.

## Auto-destroy

Instances created with `auto_destroy` carry an `expires_at`. The lab worker's
reaper destroys expired instances so the same vulnerability can be reproduced
repeatedly from a clean state.

## Why isolation matters

Lab targets must never share a network with production targets or the control
plane. The `scanner`/`wpsec-lab` network separation enforces this; disposable
instances are reset between tests.
