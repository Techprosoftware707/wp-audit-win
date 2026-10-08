# Verification engine

Verification decides whether a finding is *actually* present without turning the
target into a compromised system. Implemented in `app/services/verification.py`
and exposed at `POST /findings/{id}/verify`.

## Methods and how active they are

| Method | What it does | Activity | Approval |
|--------|--------------|----------|----------|
| `version_match` | Offline compare of detected component version vs. the affected range in the catalog | none (no network) | no |
| `endpoint_presence` | One benign `GET` to check an endpoint exists / is reachable | active-benign | no |
| `info_exposure` | One benign `GET` checking for sensitive markers in the response | active-benign | no |
| `authz_check` | Compares unauth vs. low-priv access (needs credentials) | intrusive | **yes** |
| `param_behavior` | Observes a parameter's response | intrusive | **yes** |
| `manual` | Records an operator's manual determination | none | no |

## Result classification

```
not_vulnerable · likely_vulnerable · vulnerable · confirmed · inconclusive · not_testable · unverified
```

A `confirmed` result sets `finding.confirmed = true`; `not_vulnerable` clears it.
Results feed back into the risk score.

## Safety rules

- Network-touching verification **re-checks authorization** at run time
  (`assert_scannable`); a revoked/expired authorization yields `403`.
- **Active methods require explicit approval.** Calling an active method without
  `approve: true` records a *pending* test (not executed). Approving requires the
  `verification:approve` permission.
- Active methods never attempt exploitation or state change from the API against
  production. Aggressive reproduction belongs in the isolated lab
  ([LAB.md](LAB.md)), where intrusive/destructive-classified work is contained.
