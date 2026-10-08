# PoC / Exploit Intelligence

The PoC component is an **intelligence and metadata library**, not an exploit
runner. Its job is to collect public vulnerability information, normalize it,
index it, and automatically associate it with software detected on authorized
targets — so the operator does not have to hand-search the internet for every
CVE.

## What it stores

A `PoC` record (see `app/models/poc.py`) holds metadata: CVE/CWE, affected
product/slug/version range, fixed version, attack type, auth/privilege
requirements, source URL/repo, author, publication date, a **maturity** state,
a **safety classification**, and optionally a hash/reference to a locally stored
artifact. A `Vulnerability` record is the companion catalog entry used for
matching and risk.

## Maturity & safety

Every collected record starts **UNVERIFIED**. Maturity progresses explicitly:

```
unknown → collected → parsed → static_checked → lab_tested → verified
                                          ↘ broken / obsolete / unsafe
```

Safety classification gates what may ever run automatically:

- `benign_check` — read-only existence/version check
- `active_benign` — sends a request but changes no state
- `intrusive` — changes state; **lab-only**
- `destructive` — **never** auto-run

## Collection (the collector)

`app/services/intel_sync.py` pulls from **free, public** sources:

- **CISA KEV** — the Known Exploited Vulnerabilities catalog (sets `kev=True`,
  which raises risk).
- **NVD 2.0** — recent CVEs with CVSS (no API key required; a key only raises
  rate limits).

The design does **not** hard-code a single provider; sources live in the
`poc_sources` table and more collectors can be added. Network failures are
handled gracefully (a source records its error and the sync continues).

> The collector fetches **metadata/references**. It does not blindly download
> and execute third-party code. If an artifact is stored locally it is hashed
> and left UNVERIFIED and unexecuted; static inspection and any run happen only
> in the isolated lab under operator control.

## Automatic matching

During a scan, the `poc_match` step correlates:

1. each finding's CVE → `Vulnerability` catalog (enrich CWE/CVSS/KEV) and → `PoC`
   library (records *applicable* PoC codes on the finding);
2. each detected plugin/theme + version → catalog entries whose affected range
   covers that version (creating a finding when a scanner didn't already flag
   it).

Version-range logic is in `app/services/versions.py`. Matching is read-only
intelligence; it never triggers exploitation.

## Operator workflow

```
scan finds Plugin X 1.4.2  →  CVE lookup  →  local PoC library match
    →  finding enriched + applicable PoCs listed (UNVERIFIED)
    →  operator reviews  →  (optional) reproduce in isolated lab  →  verify
```
