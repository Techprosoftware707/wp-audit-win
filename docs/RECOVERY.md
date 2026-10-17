# Administrator Recovery & Approved Remediation

Legitimate, owner-driven recovery for a WordPress site **you control** — reset a
locked-out admin, create an admin, or apply an approved component update — over
your own SSH access via WP-CLI. This is break-glass recovery, **not**
exploitation: it uses WP-CLI (which already has server-side authority); it never
bypasses authentication or exploits a vulnerability to gain access.

## Prerequisites

1. The target exists and has an **active authorization** (same gate as scanning).
2. An **SSH credential** is stored for the target (`cred_type = ssh`), with
   `meta.wp_path` pointing at the WordPress root and a host-key policy
   (`meta.known_hosts_file`, or `meta.accept_unknown_host_key: true` for TOFU).
3. The caller holds the **`recovery:execute`** permission (super-admin) for
   state-changing actions; `recovery:read` (analyst+) for read-only detection.
4. WP-CLI is available on the target host and `paramiko` on the platform host.

## Safety model (every state-changing action)

- Requires an explicit `confirm: true` **and** a `reason` (both audited).
- **Backs up the database first** (`wp db export`) and aborts if the backup
  fails — no change is attempted without a restore point.
- Verifies the result (e.g. the user still/now has the `administrator` role).
- Audited in the append-only log — **the new password is never logged**; it is
  returned once in the API/CLI response for you to store securely.
- Returns explicit **rollback** instructions.

## Actions

### Detect (read-only)

```bash
wpsec recovery detect <target-id>
```
Enumerates administrators and flags **lockout** (no admin) or **damaged
capabilities** (empty roles). Also at `POST /targets/{id}/recovery/detect`.

### Reset an existing admin's password

```bash
wpsec recovery reset-password <target-id> <admin-login-or-id> \
  --reason "owner locked out" --confirm
```
Refuses non-administrator users. Backs up, runs `wp user update <id>
--user_pass=…`, verifies, and prints the new password **once**.
Rollback: `wp db import <backup-file>`.

### Create a new admin (explicit confirmation)

```bash
wpsec recovery create-admin <target-id> <login> <email> \
  --reason "restore access" --confirm
```
Refuses an existing login. Backs up, runs `wp user create … --role=administrator`,
verifies. Rollback: `wp user delete <id> --yes` (or restore the backup).

### Approved remediation (component update)

```bash
wpsec recovery update <target-id> plugin <slug> \
  --to-version 5.9.1 --reason "patch CVE-XXXX" --confirm
```
**Never downgrades** (an explicit lower `--to-version` is refused). Backs up,
runs `wp plugin|theme update`, and reports version before/after.
Rollback: `wp db import <backup-file>`.

## Rollback procedure (general)

1. Note the `backup_file` returned by the action (lives in the WordPress dir on
   the server).
2. From the WordPress root on the server: `wp db import <backup_file>`.
3. For a created admin you want to remove: `wp user delete <id> --yes`.
4. Re-run `wpsec recovery detect <target-id>` to confirm the expected state.

## What recovery will NOT do

Create admins silently, modify a site without `confirm`, act without an active
authorization, skip the pre-change backup, log the new password, or touch a
target you are not authorized for. For aggressive exploit reproduction use the
isolated lab, not recovery.
