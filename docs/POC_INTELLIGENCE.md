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

## Artifact collection (download → hash → inspect → classify → store → index)

`app/services/poc_collector.py` implements the artifact side of the workflow for
PoC records that carry a `source_url`. It is deliberately **read-only with
respect to the artifact**: it downloads bytes, hashes them, reads them as text,
and pattern-matches markers — **there is no code path that runs, imports,
compiles, or shells out to a collected artifact.**

1. **Download (where permitted)** — `fetch_public()` fetches only `http(s)`
   public URLs. Any host resolving to a private / loopback / link-local /
   reserved address is refused (SSRF guard), every redirect hop is re-validated,
   and the body is capped at 1 MiB.
2. **Hash** — SHA-256 of the exact bytes (stored on the record and returned).
3. **Static inspection** — `static_inspect()` is a pure function that classifies
   the artifact's *potential* behaviour by scanning for markers and detects the
   language. It is a heuristic to inform the operator, never a silently-trusted
   execution gate.
4. **Classify** — the **worst** class that matched wins:
   `destructive` > `intrusive` > `active_benign` > `benign_check` > `unknown`.
5. **Store** — bytes go to MinIO object storage (`pocs/<code>/<sha>.<ext>`) with
   a local-disk fallback (`$WPSEC_DATA_DIR/pocs`) so an artifact is always
   retained. The record's `maturity` advances to `static_checked`.
6. **Index** — the record keeps `artifact_sha256`, `artifact_ref`,
   `safety_classification`, and a `test_result["collect"]` summary.

**Collection never verifies anything.** `verification_status` stays at its
current value (`unverified` by default); only the operator-driven, isolated lab
reproduction path (see [LAB.md](LAB.md)) may raise it.

Triggers:

- API: `POST /pocs/{id}/collect` (single), `POST /pocs/collect` (batch,
  `only_uncollected` + `limit`), `GET /pocs/{id}/artifact` (download as a
  plain-text attachment with `X-Content-Type-Options: nosniff`).
- CLI: `wpsec poc collect [POC_ID] [--limit N]`.
- Dashboard: **Collect artifacts** on the PoC Intelligence page; collected rows
  expose a hashed download link.

Scanner **data** (the other "files ready to run") is pre-cached into the worker
image: nuclei templates and the semgrep `p/php`/`p/wordpress` rulesets are
fetched at build time, and a content-discovery wordlist ships in the repo — so a
fresh Ubuntu 24 deployment detects without a first-use download.

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
