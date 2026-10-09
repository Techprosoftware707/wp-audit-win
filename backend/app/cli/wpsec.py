"""wpsec — command-line client for the wp-audit-win API.

Configuration (API base URL + token) is stored in ~/.config/wpsec/config.json.
Set the API base with WPSEC_API or `wpsec config set-url`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="wp-audit-win CLI (authorized security assessment).", no_args_is_help=True)
target_app = typer.Typer(help="Manage targets.", no_args_is_help=True)
scan_app = typer.Typer(help="Manage scans.", no_args_is_help=True)
finding_app = typer.Typer(help="Inspect findings.", no_args_is_help=True)
poc_app = typer.Typer(help="PoC intelligence library.", no_args_is_help=True)
lab_app = typer.Typer(help="Isolated labs.", no_args_is_help=True)
report_app = typer.Typer(help="Reports.", no_args_is_help=True)
worker_app = typer.Typer(help="Workers.", no_args_is_help=True)
config_app = typer.Typer(help="CLI configuration.", no_args_is_help=True)
app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")
app.add_typer(finding_app, name="finding")
app.add_typer(poc_app, name="poc")
app.add_typer(lab_app, name="lab")
app.add_typer(report_app, name="report")
app.add_typer(worker_app, name="worker")
app.add_typer(config_app, name="config")

console = Console()
CONFIG_PATH = Path(os.path.expanduser("~/.config/wpsec/config.json"))


def _load() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (ValueError, OSError):
            return {}
    return {}


def _save(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def _base_url() -> str:
    return os.environ.get("WPSEC_API") or _load().get("base_url") or "http://localhost:8000"


def _client(auth: bool = True) -> httpx.Client:
    headers = {}
    if auth:
        token = _load().get("token")
        if not token:
            console.print("[red]Not logged in. Run `wpsec login`.[/red]")
            raise typer.Exit(1)
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=_base_url(), headers=headers, timeout=120)


def _handle(resp: httpx.Response):
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        console.print(f"[red]HTTP {resp.status_code}:[/red] {detail}")
        raise typer.Exit(1)
    return resp.json() if resp.content else None


# ----------------------------------------------------------------- top-level
@app.command()
def login(
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
    totp: str = typer.Option("", help="TOTP code if MFA is enabled"),
):
    """Authenticate and store an access token."""
    with _client(auth=False) as c:
        data = _handle(
            c.post(
                "/auth/login",
                json={
                    "email": email,
                    "password": password,
                    "totp_code": totp or None,
                },
            )
        )
    cfg = _load()
    cfg["token"] = data["access_token"]
    cfg["base_url"] = _base_url()
    _save(cfg)
    console.print("[green]Logged in.[/green]")


@config_app.command("set-url")
def set_url(url: str):
    """Set the API base URL."""
    cfg = _load()
    cfg["base_url"] = url
    _save(cfg)
    console.print(f"API base set to {url}")


# -------------------------------------------------------------------- targets
@target_app.command("list")
def target_list():
    with _client() as c:
        rows = _handle(c.get("/targets"))
    table = Table("ID", "Name", "Host", "Authorized", "Profile")
    for t in rows:
        table.add_row(
            t["id"][:8],
            t["name"],
            t["host"],
            "[green]yes[/green]" if t["authorized"] else "[red]no[/red]",
            t["scan_profile"],
        )
    console.print(table)


@target_app.command("add")
def target_add(
    url: str = typer.Option(..., "--url"),
    name: str = typer.Option("", "--name"),
    owner: str = typer.Option("", "--owner"),
    profile: str = typer.Option("safe", "--profile"),
):
    with _client() as c:
        data = _handle(
            c.post(
                "/targets",
                json={
                    "name": name or url,
                    "base_url": url,
                    "owner": owner,
                    "scan_profile": profile,
                    "max_intensity": "standard",
                },
            )
        )
    console.print(f"[green]Created target[/green] {data['id']}")


@target_app.command("authorize")
def target_authorize(
    target_id: str,
    auth_type: str = typer.Option("written_consent", "--type"),
    by: str = typer.Option("", "--by"),
    expires: str = typer.Option("", "--expires", help="ISO date e.g. 2026-12-31"),
    scope: list[str] = typer.Option(None, "--scope", help="host/IP/CIDR (repeatable)"),
):
    """Create and immediately activate an authorization for a target."""
    body = {
        "auth_type": auth_type,
        "authorized_by": by,
        "allowed_scope": scope or [],
        "max_intensity": "standard",
    }
    if expires:
        body["expiration_date"] = f"{expires}T23:59:59+00:00"
    with _client() as c:
        authz = _handle(c.post(f"/targets/{target_id}/authorizations", json=body))
        _handle(
            c.post(
                f"/targets/{target_id}/authorizations/{authz['id']}/status",
                json={"status": "active"},
            )
        )
    console.print(f"[green]Authorization active[/green] ({authz['id']})")


# ---------------------------------------------------------------------- scans
@scan_app.command("start")
def scan_start(target_id: str, profile: str = typer.Option(None, "--profile")):
    body = {"mode": "production"}
    if profile:
        body["profile"] = profile
    with _client() as c:
        data = _handle(c.post(f"/targets/{target_id}/scan", json=body))
    console.print(f"[green]Scan {data['id']}[/green] status={data['status']}")
    console.print_json(data=data["summary"])


@scan_app.command("status")
def scan_status(scan_id: str):
    with _client() as c:
        data = _handle(c.get(f"/scans/{scan_id}"))
    console.print(
        f"Scan {scan_id} — [bold]{data['status']}[/bold] (intensity {data['effective_intensity']})"
    )
    table = Table("Step", "Status", "Note")
    for s in data.get("steps", []):
        table.add_row(s["name"], s["status"], s["error"][:60])
    console.print(table)
    console.print_json(data=data["summary"])


@scan_app.command("stop")
def scan_stop(scan_id: str):
    with _client() as c:
        data = _handle(c.post(f"/scans/{scan_id}/cancel"))
    console.print(f"Scan {scan_id} -> {data['status']}")


# ------------------------------------------------------------------- findings
@finding_app.command("list")
def finding_list(
    scan_id: str = typer.Argument(None), target_id: str = typer.Option(None, "--target")
):
    params = {}
    if scan_id:
        params["scan_id"] = scan_id
    if target_id:
        params["target_id"] = target_id
    with _client() as c:
        rows = _handle(c.get("/findings", params=params))
    table = Table("Code", "Sev", "Risk", "Title", "CVE", "Status")
    for f in rows:
        table.add_row(
            f["finding_code"],
            f["severity"],
            f"{f['risk_score']:.0f}",
            f["title"][:44],
            f["cve"] or "",
            f["status"],
        )
    console.print(table)


@finding_app.command("show")
def finding_show(finding_id: str):
    with _client() as c:
        data = _handle(c.get(f"/findings/{finding_id}"))
    console.print_json(data=data)


# ----------------------------------------------------------------------- poc
@poc_app.command("search")
def poc_search(query: str = typer.Argument(""), cve: str = typer.Option(None, "--cve")):
    params = {}
    if query:
        params["q"] = query
    if cve:
        params["cve"] = cve
    with _client() as c:
        rows = _handle(c.get("/pocs", params=params))
    table = Table("Code", "CVE", "Title", "Maturity", "Safety")
    for p in rows:
        table.add_row(
            p["poc_code"],
            p["cve"] or "",
            p["title"][:40],
            p["maturity"],
            p["safety_classification"],
        )
    console.print(table)


@poc_app.command("update")
def poc_update():
    """Trigger a sync of PoC/vulnerability intelligence sources."""
    with _client() as c:
        data = _handle(c.post("/pocs/sync", json={}))
    console.print_json(data=data)


@poc_app.command("collect")
def poc_collect(
    poc_id: str = typer.Argument(None, help="Collect one PoC; omit to batch uncollected"),
    limit: int = typer.Option(25, "--limit"),
):
    """Download + statically classify PoC artifacts. Never executes them.

    Artifacts are fetched (SSRF-guarded, size-capped), hashed, statically
    inspected, classified by safety, and stored. Everything stays UNVERIFIED.
    """
    with _client() as c:
        if poc_id:
            data = _handle(c.post(f"/pocs/{poc_id}/collect"))
            console.print_json(data=data)
            return
        data = _handle(
            c.post("/pocs/collect", json={"only_uncollected": True, "limit": limit})
        )
    table = Table("Code", "Status", "Safety", "Lang", "SHA-256")
    for r in data.get("results", []):
        table.add_row(
            r.get("poc_code", ""),
            r.get("status", ""),
            r.get("safety_classification", ""),
            r.get("language", ""),
            (r.get("sha256") or "")[:16],
        )
    console.print(table)
    console.print(f"collected {data.get('collected', 0)}/{data.get('requested', 0)}")


@poc_app.command("test")
def poc_test(poc_id: str):
    """PoC testing is operator-driven in the isolated lab (see docs/LAB.md)."""
    console.print(
        f"PoC {poc_id}: automated testing runs in the isolated lab workflow and "
        "requires explicit operator approval. See docs/LAB.md and the Lab section "
        "of the dashboard."
    )


# ----------------------------------------------------------------------- lab
@lab_app.command("create")
def lab_create(name: str, wp_version: str = typer.Option("latest", "--wp")):
    with _client() as c:
        data = _handle(
            c.post(
                "/labs",
                json={
                    "name": name,
                    "template": {"wp_version": wp_version},
                    "auto_destroy": True,
                },
            )
        )
    console.print(f"[green]Lab {data['id']}[/green] {data['name']}")


@lab_app.command("destroy")
def lab_destroy(instance_id: str):
    with _client() as c:
        data = _handle(c.delete(f"/labs/instances/{instance_id}"))
    console.print(f"Instance {instance_id} -> {data['status']}")


# -------------------------------------------------------------------- reports
@report_app.command("generate")
def report_generate(
    scan_id: str, fmt: str = typer.Option("html", "--format"), out: str = typer.Option("", "--out")
):
    with _client() as c:
        rep = _handle(c.post(f"/scans/{scan_id}/report", json={"report_format": fmt}))
        if rep["status"] != "ready":
            console.print(f"[red]Report {rep['status']}[/red]: {rep.get('error', '')}")
            raise typer.Exit(1)
        content = c.get(f"/reports/{rep['id']}/download").content
    path = out or f"report-{scan_id[:8]}.{'md' if fmt == 'markdown' else fmt}"
    Path(path).write_bytes(content)
    console.print(f"[green]Report written[/green] -> {path}")


# -------------------------------------------------------------------- workers
@worker_app.command("list")
def worker_list():
    with _client() as c:
        rows = _handle(c.get("/workers"))
    table = Table("Name", "Status", "Queues", "Jobs", "CPU", "RAM(MB)", "Last heartbeat")
    for w in rows:
        table.add_row(
            w["name"],
            w["status"],
            w["queues"],
            str(w["job_count"]),
            str(w["cpu_percent"]),
            str(w["ram_mb"]),
            str(w["last_heartbeat"] or ""),
        )
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
