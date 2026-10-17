# Security Limitations & Scope

An honest statement of what wp-audit-win does, what it deliberately does **not**
do, and the conditions under which findings are reliable. Read this before
relying on a scan result or a recovery action.

## What this tool is

A defensive security auditor and owner-driven recovery tool for WordPress sites
you **own or have explicit written authorization to test**. It finds likely
weaknesses, validates them safely, prioritizes them, and helps you remediate and
recover — with evidence and reproducibility over exploitation.

## Hard boundaries (enforced in code, not just docs)

- **Authorization-gated.** Active scanning and every recovery/remediation action
  require an active authorization covering the target host and time window.
- **Scope-confined.** Target HTTP is restricted to the authorized scope; every
  redirect hop is re-validated; link-local/metadata/loopback/private ranges are
  blocked for the public PoC fetcher, and the scanner only reaches in-scope
  hosts. See [SECURITY.md](SECURITY.md).
- **No autonomous compromise.** The platform never auto-exploits a live site,
  creates admin accounts through an exploit, steals credentials or session
  tokens, runs arbitrary commands on third-party systems, deploys web shells,
  or escalates to host root. Aggressive reproduction is confined to the isolated
  lab and is operator-approved.
- **Collected PoCs are never executed** — they are downloaded, hashed, statically
  classified, and left UNVERIFIED. See [POC_INTELLIGENCE.md](POC_INTELLIGENCE.md).
- **Recovery is owner-driven and reversible.** Password reset / admin creation /
  component updates run only over the owner's stored SSH credential via WP-CLI,
  require an explicit `confirm` + reason + the super-admin `recovery:execute`
  permission, back up the database first, and are audited (never the password).
  See [RECOVERY.md](RECOVERY.md).

## Detection confidence — read findings correctly

- **Version-based warnings are not confirmations.** An outdated plugin is a
  *reason to investigate*, not proof of exploitability. The tool labels findings
  `confirmed` vs `likely_vulnerable` vs `unverified` and never claims admin
  access is possible solely because a component is outdated.
- **Safe validation is non-destructive** (version match, benign endpoint
  presence, information-exposure GETs). Active methods are approval-gated and, by
  default, reproduction happens in the lab — so a "confirmed" finding reflects a
  safe check, not a live exploit.
- **Static source analysis is heuristic.** semgrep/pattern matches flag risky
  code (missing `current_user_can()`, open `permission_callback`, unsafe SQL);
  they are candidates to review, distinguished from verified issues.

## Environmental limitations

- **External scanners degrade gracefully.** nmap/nuclei/wpscan/nikto/ffuf/ZAP/
  semgrep/gitleaks/WP-CLI each **self-skip with a reason** when their binary,
  daemon, source tree, or SSH credential is absent. A base scan still completes;
  install the `scanners` profile for full coverage.
- **Vulnerability intelligence is as fresh as its sync.** NVD/CISA-KEV/OSV/GitHub
  Advisory/WPScan/WordPress.org feeds are cached locally; coverage depends on the
  last sync and on optional (free) API tokens for rate limits. No paid service is
  required for basic operation.
- **No guarantee of completeness.** Absence of a finding is not proof of
  security. Zero-days, custom-code bugs, and logic flaws beyond the checks here
  will not be found. This tool complements, not replaces, manual review.

## Operational cautions

- Recovery/remediation change a live (owned) site: always keep the pre-change
  database backup the tool creates, and test the documented rollback.
- The companion plugin is read-only and signs its reports, but it still exposes
  configuration data to any site admin — install it only where appropriate and
  remove it when the audit is done (its `uninstall.php` cleans up).
- Reports can contain sensitive detail (paths, versions, evidence). Treat
  exported JSON/CSV/HTML/PDF as confidential.

## Not built (by design)

Autonomous exploitation, credential/session theft, persistence/backdoors,
stealth/evasion, destructive payloads, a "scan arbitrary site" path, and the
separate remote-administration/agent platform (never implemented in this repo).
See [ACCEPTANCE_REPORT.md](ACCEPTANCE_REPORT.md) §4.
