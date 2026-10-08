# Security & responsible use

## Scope of the tool

wp-audit-win is an **authorized** WordPress security assessment platform. It is
for systems you own or have explicit written permission to test. It deliberately
**does not** implement:

- unrestricted scanning of arbitrary third-party sites (every active action is
  authorization-gated — see [AUTHORIZATION.md](AUTHORIZATION.md));
- stealth, evasion, or anti-detection features;
- persistence, credential theft, or destructive payloads;
- automatic download-and-execute of exploit code (see
  [POC_INTELLIGENCE.md](POC_INTELLIGENCE.md)).

The PoC component is an *intelligence/metadata* layer; active exploit
verification is operator-driven, lab-isolated, and human-approved
([VERIFICATION.md](VERIFICATION.md), [LAB.md](LAB.md)).

## Platform hardening

| Control | Implementation |
|---------|----------------|
| Transport | TLS at the Caddy proxy; HSTS + security headers; secure-by-default |
| AuthN | argon2 password hashing; JWT access/refresh; TOTP MFA-ready |
| AuthZ | per-endpoint RBAC matrix (`app/core/rbac.py`); 5 roles |
| API auth | bearer tokens and hashed API keys (shown once) |
| Secrets at rest | credentials encrypted with Fernet (`WPSEC_CREDENTIAL_KEY`) |
| Secrets in logs | log filter redacts tokens/passwords/keys; audit never stores secrets |
| CSRF | token (not cookie) auth for the API avoids CSRF on state-changing calls |
| Rate limiting | login throttling (Redis or in-process) |
| Audit | append-only `audit_logs`: who / what / where / when / result |
| Input validation | Pydantic schemas on every request body |
| Container isolation | scanner workers `cap_drop: ALL`, `no-new-privileges`; non-root images |
| Network | control-plane vs scanner networks; **no Docker socket** on api/web |
| Config safety | production refuses to boot with default/weak `SECRET_KEY`/`CREDENTIAL_KEY` |

## Secrets management

`install.sh` generates all secrets with `openssl` into `.env` (chmod 600).
`WPSEC_CREDENTIAL_KEY` is a Fernet key used to encrypt stored target
credentials. Rotating it re-keys future writes; existing ciphertext must be
re-encrypted (planned helper — see [STATUS.md](STATUS.md)).

## Reporting issues

Treat generated reports and evidence as confidential — they describe real
weaknesses in authorized systems. Store backups (`backup.sh` output) securely;
the archive contains `.env` and evidence.
