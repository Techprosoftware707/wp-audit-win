=== wp-audit-win Companion ===
Contributors: wp-audit-win
Tested up to: 6.6
Requires at least: 6.2
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only, capability-restricted audit API for WordPress sites you own, used by
the wp-audit-win security-audit platform.

== Description ==

This companion plugin exposes a small, READ-ONLY REST API that reports your
site's core/PHP/plugin/theme versions and security-configuration flags, and runs
safe permission/configuration checks. It is designed for an owner-driven audit.

Security model:

* Every route requires the `manage_options` capability (site administrator).
  WordPress authenticates the caller (logged-in cookie + nonce, or an
  Application Password); the plugin only authorizes.
* All endpoints are READ-ONLY. The plugin never creates users, changes roles,
  escalates privileges, installs anything, or edits content.
* Reports contain ONLY versions, flags, counts and configuration booleans —
  never credentials, auth salts/keys, nonces, customer PII, or order data.
* The full report is integrity-protected with an HMAC-SHA256 signature keyed by
  a per-site secret generated on activation. The secret never leaves the site;
  only the digest is published, so a consumer can verify integrity without ever
  learning the key.

== REST endpoints ==

Namespace: `wp-audit-win/v1`

* `GET /wp-json/wp-audit-win/v1/status`  — inventory + configuration (unsigned)
* `GET /wp-json/wp-audit-win/v1/checks`  — safe security-configuration checks
* `GET /wp-json/wp-audit-win/v1/report`  — full HMAC-signed report envelope

Authenticate with an Application Password (Users → Profile → Application
Passwords) for machine-to-machine use.

== Installation ==

1. Build the ZIP: `wordpress-plugin/build.sh` (produces
   `wp-audit-win-companion.zip`).
2. In wp-admin: Plugins → Add New → Upload Plugin → choose the ZIP → Activate.
3. Create an Application Password for a site-admin account and point
   wp-audit-win at `https://your-site/wp-json/wp-audit-win/v1/report`.

== Uninstall ==

Deleting the plugin removes its two options (`wpawc_report_key`,
`wpawc_installed_version`) via uninstall.php and leaves no other residue.

== Changelog ==

= 0.1.0 =
* Initial read-only audit API with signed reports.
