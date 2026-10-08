"""WordPress fingerprint & enumeration step.

Passive/safe discovery of WordPress core, plugins, themes, users, and exposed
endpoints by reading public responses. Creates informational/low/medium findings
for common exposures (version disclosure, user enumeration, XML-RPC enabled).
"""

from __future__ import annotations

import json

from app.models.enums import AssetType, Severity, VerificationStatus
from app.workers import http
from app.workers.base import StepContext
from app.workers.parsers import wp


def run(ctx: StepContext) -> dict:
    base = ctx.target.base_url.rstrip("/")
    home = http.fetch(base, scope=ctx.scope)
    if not home.ok:
        return {"skipped": True, "reason": f"base URL unreachable: {home.error}"}

    is_wp = wp.looks_like_wordpress(home.text, home.headers)
    core_version = wp.generator_version(home.text)

    plugins = wp.extract_plugins(home.text)
    themes = wp.extract_themes(home.text)

    # readme.html — version disclosure.
    readme_found = False
    readme = http.fetch(f"{base}/readme.html", scope=ctx.scope)
    if readme.ok and readme.status_code == 200 and "wordpress" in readme.text.lower():
        readme_found = True
        rv = wp.readme_version(readme.text)
        if rv and not core_version:
            core_version = rv
        f = ctx.add_finding(
            title="WordPress version disclosed via readme.html",
            severity=Severity.INFO.value,
            dedup_key=f"sig:readme:{ctx.target.host}",
            detector="wp_fingerprint",
            description=f"readme.html is publicly accessible (version {rv or 'unknown'}).",
            affected_asset=f"{base}/readme.html",
            cwe="CWE-200",
            verification_status=VerificationStatus.CONFIRMED.value,
            remediation="Remove or block public access to readme.html.",
            auth_required=False,
        )
        f.confirmed = True

    # REST API.
    rest_enabled = False
    rest = http.fetch(f"{base}/wp-json/", scope=ctx.scope)
    if (
        rest.ok
        and rest.status_code == 200
        and "application/json" in rest.headers.get("content-type", "")
    ):
        rest_enabled = True
        ctx.add_asset(AssetType.REST_ROUTE.value, f"{base}/wp-json/", meta={"status": 200})

        users_resp = http.fetch(f"{base}/wp-json/wp/v2/users", scope=ctx.scope)
        if users_resp.ok and users_resp.status_code == 200:
            try:
                payload = json.loads(users_resp.text)
            except (ValueError, json.JSONDecodeError):
                payload = None
            users = wp.rest_users(payload) if payload is not None else []
            if users:
                for u in users:
                    ctx.add_wp_user(
                        login=u.get("slug") or u.get("name") or "unknown",
                        display_name=u.get("name", ""),
                        wp_user_id=u.get("id"),
                        source="rest",
                        detail=u,
                    )
                f = ctx.add_finding(
                    title="Username enumeration via REST API",
                    severity=Severity.MEDIUM.value,
                    dedup_key=f"sig:rest-user-enum:{ctx.target.host}",
                    detector="wp_fingerprint",
                    description=(
                        f"The /wp-json/wp/v2/users endpoint returned {len(users)} user(s), "
                        "enabling username enumeration."
                    ),
                    affected_asset=f"{base}/wp-json/wp/v2/users",
                    cwe="CWE-200",
                    verification_status=VerificationStatus.CONFIRMED.value,
                    remediation="Restrict the users REST endpoint for unauthenticated requests.",
                    auth_required=False,
                )
                f.confirmed = True
                ctx.add_evidence(
                    finding=f,
                    kind="request_response",
                    request=f"GET {base}/wp-json/wp/v2/users",
                    response=users_resp.text[:4000],
                    http_status=users_resp.status_code,
                    headers=users_resp.headers,
                )

    # XML-RPC.
    xmlrpc_enabled = False
    xr = http.fetch(f"{base}/xmlrpc.php", scope=ctx.scope)
    if xr.ok and wp.xmlrpc_enabled(xr.status_code, xr.text):
        xmlrpc_enabled = True
        ctx.add_asset(AssetType.XMLRPC.value, f"{base}/xmlrpc.php", meta={"status": xr.status_code})
        f = ctx.add_finding(
            title="XML-RPC interface enabled",
            severity=Severity.LOW.value,
            dedup_key=f"sig:xmlrpc:{ctx.target.host}",
            detector="wp_fingerprint",
            description=(
                "xmlrpc.php is enabled. It can be abused for brute-force amplification "
                "(system.multicall) and pingback SSRF/DDoS."
            ),
            affected_asset=f"{base}/xmlrpc.php",
            cwe="CWE-306",
            verification_status=VerificationStatus.CONFIRMED.value,
            remediation="Disable XML-RPC if unused, or restrict access.",
            auth_required=False,
        )
        f.confirmed = True

    # login URL / multisite hint.
    login = http.fetch(f"{base}/wp-login.php", scope=ctx.scope)
    login_url = login.url if login.ok else ""

    # Record discovered components.
    if core_version:
        ctx.add_technology(
            "WordPress",
            version=core_version,
            category="cms",
            source="wp_fingerprint",
            confidence=90,
        )
    for slug, ver in plugins.items():
        ctx.add_plugin(
            slug, name=slug, version=ver, status="active", source="passive", confidence=70
        )
    for slug, ver in themes.items():
        ctx.add_theme(slug, name=slug, version=ver, source="passive", confidence=70)

    ctx.set_wp_info(
        is_wordpress=is_wp,
        core_version=core_version,
        readme_found=readme_found,
        xmlrpc_enabled=xmlrpc_enabled,
        rest_api_enabled=rest_enabled,
        login_url=login_url,
        detection={
            "generator": bool(core_version),
            "plugins_found": len(plugins),
            "themes_found": len(themes),
        },
    )

    return {
        "is_wordpress": is_wp,
        "core_version": core_version,
        "plugins": list(plugins.keys()),
        "themes": list(themes.keys()),
        "rest_api_enabled": rest_enabled,
        "xmlrpc_enabled": xmlrpc_enabled,
    }
