# Authorization model

Authorization is a **first-class database object** and the platform's primary
safety control. No active scan step runs against a production target unless an
`ACTIVE` authorization covers it.

## The `Authorization` object

| Field | Meaning |
|-------|---------|
| `target_id` | the target it authorizes |
| `status` | `pending` → `active` → (`expired` \| `revoked`) |
| `auth_type` | `written_consent`, `internal_asset`, `bug_bounty_scope`, `lab`, `other` |
| `authorized_by` | who granted it |
| `reference` | ticket / document / URL |
| `start_date` / `expiration_date` | the time window |
| `allowed_scope` | list of hostnames, IPs, or CIDRs this covers |
| `testing_profile` / `max_intensity` | caps on aggressiveness |

## Enforcement

`app/services/authorization.py::assert_scannable()` is called by the scan
orchestrator **and** re-checked by the `authorization` step at run time (so a
revocation between enqueue and execution stops the scan). A target is scannable
only if an authorization is **all** of:

1. `status == active`
2. `start_date <= now <= expiration_date` (expiry auto-flips `active`→`expired`)
3. `allowed_scope` matches the target host (exact, `*.wildcard`, IP, or CIDR).
   An empty scope defaults to the target's own host only.

Any active verification that sends network traffic is gated the same way.

## Intensity clamping

The effective intensity of a scan is the **minimum** of:

```
requested profile  ∧  target.max_intensity  ∧  authorization.max_intensity  ∧  WPSEC_MAX_INTENSITY (global ceiling)
```

Order: `passive < safe < standard < aggressive`. `passive` skips active port
scanning and limits nuclei to detection templates; active ZAP scanning requires
`standard`+.

## In the UI/API

- The target list and detail views show an **authorized / not-authorized**
  badge derived from a live evaluation.
- `POST /targets/{id}/scan` returns **403** with a reason when not authorized.
- Every authorization create / activate / revoke is written to the audit log.

## What this prevents

The system deliberately has **no** feature to scan an arbitrary URL without
first recording and activating an authorization for it. This is the mechanism
that keeps the platform an *authorized* assessment tool.
