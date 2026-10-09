"""PoC / exploit artifact collector.

Implements the brief's collection workflow for publicly-known proof-of-concept
material:

    DOWNLOAD (where permitted) -> HASH -> STATIC INSPECTION -> CLASSIFY
    -> STORE -> INDEX

Hard safety rules (enforced here and relied on across the platform):

* **Nothing collected is ever executed.** This module only downloads bytes,
  hashes them, reads them as text, and pattern-matches markers. There is no
  code path that runs, imports, compiles, or shells out to a collected
  artifact. Running a PoC is exclusively the operator-driven, isolated lab
  reproduction path (see docs/LAB.md), which is human-approved.
* **Everything collected starts UNVERIFIED.** Collection downloads and
  statically classifies an artifact; it never asserts that the PoC works.
  ``verification_status`` is left at its current value (``unverified`` by
  default) and is only ever raised by the lab path.
* **Fetching is SSRF-safe.** Only ``http``/``https`` public URLs are fetched;
  any URL whose host resolves to a private/loopback/link-local/reserved
  address is refused, and every redirect hop is re-validated. The download is
  size-capped so a hostile source cannot exhaust memory/disk.

The static classifier is deliberately conservative: when in doubt it escalates
the safety class (``destructive`` > ``intrusive`` > ``active_benign`` >
``benign_check`` > ``unknown``) so an operator sees the *worst* plausible
behaviour before deciding whether lab reproduction is warranted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from app.core.logging import get_logger
from app.models.base import utcnow
from app.models.enums import PoCMaturity, SafetyClass
from app.models.poc import PoC
from app.services import evidence as evidence_service

log = get_logger("poc_collector")

DATA_DIR = os.environ.get("WPSEC_DATA_DIR", os.path.join(os.getcwd(), "data"))

MAX_POC_BYTES = 1_048_576  # 1 MiB — PoCs are source/scripts, not payloads of size
FETCH_TIMEOUT = 20.0
MAX_REDIRECTS = 4
ALLOWED_SCHEMES = {"http", "https"}
USER_AGENT = "wp-audit-win/0.1 (authorized PoC intelligence collector)"

# Test hook mirroring app.workers.http so the fetch path can be exercised
# without real network access.
_TEST_TRANSPORT: httpx.BaseTransport | None = None


def set_transport_for_tests(transport: httpx.BaseTransport | None) -> None:
    global _TEST_TRANSPORT
    _TEST_TRANSPORT = transport


# --------------------------------------------------------------------------- #
# Static inspection / safety classification (PURE — no I/O, never executes)
# --------------------------------------------------------------------------- #

# Ordered worst-first. The first category with a hit wins the classification.
_DESTRUCTIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("rm -rf", re.compile(r"\brm\s+-[rfRose]*[rf][rfRose]*\b")),
    ("mkfs", re.compile(r"\bmkfs(\.\w+)?\b")),
    ("dd to device", re.compile(r"\bdd\s+if=.*\bof=/dev/")),
    ("overwrite block device", re.compile(r">\s*/dev/(sd|nvme|hd|xvd|vd)\w*")),
    ("fork bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
    ("drop database/table", re.compile(r"\bDROP\s+(DATABASE|TABLE|SCHEMA)\b", re.I)),
    ("truncate table", re.compile(r"\bTRUNCATE\s+(TABLE\s+)?\w", re.I)),
    ("unconditional delete", re.compile(r"\bDELETE\s+FROM\s+\w+\s*;", re.I)),
    ("wp db drop/reset", re.compile(r"\bwp\s+db\s+(drop|reset)\b", re.I)),
    ("recursive tree delete", re.compile(r"\b(shutil\.rmtree|rmtree|RemoveDirectory)\b")),
    ("format drive", re.compile(r"\bformat\s+[a-z]:", re.I)),
]

_INTRUSIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Command / code execution primitives.
    ("reverse shell (bash /dev/tcp)", re.compile(r"/dev/tcp/")),
    ("reverse shell (nc -e)", re.compile(r"\bnc(at)?\b[^\n]*\s-e\b")),
    ("interactive shell spawn", re.compile(r"\b(/bin/(ba)?sh)\b[^\n]*\s-i\b")),
    ("php code exec", re.compile(r"\b(system|shell_exec|passthru|popen|proc_open|exec)\s*\(")),
    ("php eval/assert", re.compile(r"\b(eval|assert|create_function)\s*\(")),
    ("python code exec", re.compile(r"\b(os\.system|subprocess\.(call|run|Popen)|pty\.spawn)\b")),
    ("python eval/exec", re.compile(r"(?<![\w.])(eval|exec)\s*\(")),
    ("java runtime exec", re.compile(r"Runtime\.getRuntime\(\)\.exec")),
    ("socket shell", re.compile(r"\bfsockopen\s*\(|SOCK_STREAM")),
    # State-changing / account-creating actions against WordPress.
    ("wp user create/update", re.compile(r"\bwp\s+user\s+(create|update)\b", re.I)),
    ("insert/update wp_users", re.compile(r"\b(INSERT\s+INTO|UPDATE)\s+\w*users\b", re.I)),
    ("privilege field write", re.compile(r"wp_capabilities|wp_user_level|set_role\s*\(", re.I)),
    # Webshell drop / arbitrary file write.
    ("file upload move", re.compile(r"\bmove_uploaded_file\s*\(")),
    ("arbitrary file write", re.compile(r"\b(file_put_contents|fwrite|fopen)\s*\([^)]*['\"]w")),
]

_ACTIVE_BENIGN_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "http client (python)",
        re.compile(r"\b(requests\.(get|post|put|head)|urllib|http\.client)\b"),
    ),
    ("http client (curl/wget)", re.compile(r"\b(curl|wget)\b")),
    ("http client (js fetch/xhr)", re.compile(r"\b(fetch\s*\(|XMLHttpRequest|axios)\b")),
    ("wp login endpoint", re.compile(r"wp-login\.php|admin-ajax\.php|xmlrpc\.php")),
    ("wp rest write", re.compile(r"/wp-json/[^\s'\"]*", re.I)),
]

_BENIGN_CHECK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("version/readme probe", re.compile(r"readme\.txt|/style\.css|\?ver=|changelog", re.I)),
    ("generator/version string", re.compile(r"\bgenerator\b|\bversion\b", re.I)),
    ("rest discovery", re.compile(r"/wp-json/wp/v2", re.I)),
]

_LANG_HINTS: list[tuple[str, re.Pattern]] = [
    ("php", re.compile(r"<\?php|\$_(GET|POST|REQUEST|SERVER)\b")),
    ("python", re.compile(r"^#!.*\bpython|^\s*(import|from)\s+\w+|^\s*def\s+\w+\s*\(", re.M)),
    ("shell", re.compile(r"^#!.*\b(ba)?sh\b|^\s*(echo|export|sudo)\s", re.M)),
    ("javascript", re.compile(r"\b(require|module\.exports|=>|const\s+\w+\s*=|document\.)")),
    ("go", re.compile(r"^\s*package\s+main\b|^\s*func\s+\w+\s*\(", re.M)),
    ("c", re.compile(r"#include\s*<\w+\.h>|\bint\s+main\s*\(")),
    ("ruby", re.compile(r"^\s*require\s+['\"]|\bputs\b|\bend\b", re.M)),
]

_EXT_BY_LANG = {
    "php": "php",
    "python": "py",
    "shell": "sh",
    "javascript": "js",
    "go": "go",
    "c": "c",
    "ruby": "rb",
}


@dataclass
class StaticInspection:
    safety_class: SafetyClass
    language: str
    markers: list[str] = field(default_factory=list)
    byte_len: int = 0
    line_count: int = 0

    def to_dict(self) -> dict:
        return {
            "safety_classification": self.safety_class.value,
            "language": self.language,
            "markers": self.markers,
            "byte_len": self.byte_len,
            "line_count": self.line_count,
        }


def _detect_language(text: str, filename_hint: str = "") -> str:
    ext = os.path.splitext(urlparse(filename_hint).path)[1].lower().lstrip(".")
    by_ext = {
        "php": "php",
        "py": "python",
        "sh": "shell",
        "bash": "shell",
        "js": "javascript",
        "mjs": "javascript",
        "go": "go",
        "c": "c",
        "h": "c",
        "rb": "ruby",
    }
    if ext in by_ext:
        return by_ext[ext]
    for lang, pat in _LANG_HINTS:
        if pat.search(text):
            return lang
    return "text"


def static_inspect(text: str, filename_hint: str = "") -> StaticInspection:
    """Classify an artifact's *potential* behaviour WITHOUT running it.

    Pure function: pattern-matches the text for markers of destructive,
    intrusive (state-changing / code-exec), active-but-benign, or read-only
    behaviour and returns the worst class that matched. This is a heuristic to
    inform an operator, never an execution gate that is silently trusted.
    """
    markers: list[str] = []
    safety = SafetyClass.UNKNOWN

    def _scan(patterns: list[tuple[str, re.Pattern]]) -> bool:
        hit = False
        for label, pat in patterns:
            if pat.search(text):
                markers.append(label)
                hit = True
        return hit

    # Scan every category so the operator sees all markers, but the recorded
    # class is the worst one that matched.
    destructive = _scan(_DESTRUCTIVE_PATTERNS)
    intrusive = _scan(_INTRUSIVE_PATTERNS)
    active = _scan(_ACTIVE_BENIGN_PATTERNS)
    benign = _scan(_BENIGN_CHECK_PATTERNS)

    if destructive:
        safety = SafetyClass.DESTRUCTIVE
    elif intrusive:
        safety = SafetyClass.INTRUSIVE
    elif active:
        safety = SafetyClass.ACTIVE_BENIGN
    elif benign:
        safety = SafetyClass.BENIGN_CHECK
    else:
        safety = SafetyClass.UNKNOWN

    return StaticInspection(
        safety_class=safety,
        language=_detect_language(text, filename_hint),
        markers=markers,
        byte_len=len(text.encode("utf-8", errors="replace")),
        line_count=text.count("\n") + 1,
    )


# --------------------------------------------------------------------------- #
# SSRF-safe public fetch (download where permitted)
# --------------------------------------------------------------------------- #


@dataclass
class FetchResult:
    data: bytes | None = None
    content_type: str = ""
    final_url: str = ""
    truncated: bool = False
    error: str = ""


def _resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def _host_is_public(host: str) -> tuple[bool, str]:
    """A PoC source must live on the public internet.

    Unlike the scanner's scope guard (which trusts the operator-authorized
    scope, possibly an internal host), the collector pulls from arbitrary
    public URLs, so any host resolving into private/loopback/link-local/
    reserved space is refused to prevent SSRF into the deployment's own
    network or cloud metadata.
    """
    if not host:
        return False, "no host"
    addrs = _resolve(host)
    if not addrs:
        return False, f"cannot resolve host {host!r}"
    for ip in addrs:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"invalid resolved address {ip!r}"
        if (
            a.is_private
            or a.is_loopback
            or a.is_link_local
            or a.is_multicast
            or a.is_unspecified
            or a.is_reserved
        ):
            return False, f"host resolves to non-public address {ip}"
    return True, ""


def _check_url(url: str) -> tuple[bool, str]:
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEMES:
        return False, f"unsupported scheme {p.scheme!r}"
    return _host_is_public(p.hostname or "")


def fetch_public(url: str) -> FetchResult:
    """Download bytes from a public http(s) URL with SSRF + size guards.

    Redirects are followed manually (max :data:`MAX_REDIRECTS`) and every hop
    is re-validated. The body is read in a streaming, size-capped loop.
    """
    url = (url or "").strip()
    ok, why = _check_url(url)
    if not ok:
        return FetchResult(error=f"blocked: {why}")

    current = url
    try:
        with httpx.Client(
            transport=_TEST_TRANSPORT,
            timeout=FETCH_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            trust_env=True,
        ) as client:
            for _ in range(MAX_REDIRECTS + 1):
                with client.stream("GET", current) as r:
                    if r.is_redirect and r.headers.get("location"):
                        nxt = urljoin(current, r.headers["location"])
                        ok, why = _check_url(nxt)
                        if not ok:
                            return FetchResult(
                                final_url=current,
                                error=f"redirect blocked: {why} ({nxt})",
                            )
                        current = nxt
                        continue
                    if r.status_code >= 400:
                        return FetchResult(
                            final_url=str(r.url),
                            error=f"HTTP {r.status_code}",
                        )
                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    for chunk in r.iter_bytes():
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > MAX_POC_BYTES:
                            truncated = True
                            break
                    data = b"".join(chunks)[:MAX_POC_BYTES]
                    return FetchResult(
                        data=data,
                        content_type=r.headers.get("content-type", "").split(";")[0].strip(),
                        final_url=str(r.url),
                        truncated=truncated,
                    )
            return FetchResult(final_url=current, error="too many redirects")
    except httpx.HTTPError as exc:
        return FetchResult(final_url=current, error=f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# Storage (MinIO, local-disk fallback) — mirrors app.services.reporting
# --------------------------------------------------------------------------- #


def _safe_ext(url: str, language: str) -> str:
    raw = os.path.splitext(urlparse(url).path)[1].lower().lstrip(".")
    if raw and re.fullmatch(r"[a-z0-9]{1,8}", raw):
        return raw
    return _EXT_BY_LANG.get(language, "txt")


def _store(key: str, data: bytes, content_type: str) -> str:
    stored = evidence_service.put_artifact(key, data, content_type or "application/octet-stream")
    if stored:
        return f"minio://{key}"
    # Local fallback so a PoC is always retained even without object storage.
    path = os.path.join(DATA_DIR, "pocs")
    os.makedirs(path, exist_ok=True)
    fname = key.replace("/", "_")
    fpath = os.path.join(path, fname)
    with open(fpath, "wb") as fh:
        fh.write(data)
    return f"file://{fpath}"


def load_artifact(poc: PoC) -> tuple[bytes, str] | None:
    """Return (bytes, content_type) for a collected artifact, or None."""
    ref = poc.artifact_ref or ""
    ct = "text/plain; charset=utf-8"
    if ref.startswith("file://"):
        path = ref[len("file://") :]
        if os.path.exists(path):
            with open(path, "rb") as fh:
                return fh.read(), ct
        return None
    if ref.startswith("minio://"):
        data = evidence_service.get_artifact(ref[len("minio://") :])
        return (data, ct) if data is not None else None
    return None


# --------------------------------------------------------------------------- #
# Orchestration: download -> hash -> inspect -> classify -> store -> index
# --------------------------------------------------------------------------- #


def collect(db, poc: PoC, *, fetcher=None) -> dict:
    """Collect and statically classify one PoC's artifact. Never executes it.

    ``fetcher`` is injectable (defaults to :func:`fetch_public`) so tests can
    drive the pipeline deterministically without network access.
    """
    fetcher = fetcher or fetch_public
    url = (poc.source_url or "").strip()
    now = utcnow()

    def _finish(result: dict) -> dict:
        # Record the outcome under test_result['collect'] (reassign for JSON
        # dirty-tracking). verification_status is intentionally NOT raised here:
        # collection downloads + classifies, it never verifies.
        poc.last_tested_at = now
        poc.test_result = {**(poc.test_result or {}), "collect": result}
        db.flush()
        return result

    if not url:
        return _finish({"status": "no_source_url"})

    fr = fetcher(url)
    if fr.error or fr.data is None:
        return _finish(
            {
                "status": "fetch_failed",
                "url": url,
                "error": fr.error or "empty response",
                "final_url": fr.final_url,
            }
        )

    data = fr.data
    sha = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8", errors="replace")
    insp = static_inspect(text, filename_hint=fr.final_url or url)

    ext = _safe_ext(fr.final_url or url, insp.language)
    key = f"pocs/{poc.poc_code}/{sha}.{ext}"
    ref = _store(key, data, fr.content_type)

    poc.artifact_sha256 = sha
    poc.artifact_ref = ref
    poc.safety_classification = insp.safety_class.value
    # Collection terminal maturity: statically checked (downloaded + parsed +
    # inspected). Lab testing / verification is a separate operator-driven step.
    poc.maturity = PoCMaturity.STATIC_CHECKED.value

    result = {
        "status": "collected",
        "url": url,
        "final_url": fr.final_url,
        "sha256": sha,
        "bytes": len(data),
        "truncated": fr.truncated,
        "content_type": fr.content_type,
        "artifact_ref": ref,
        **insp.to_dict(),
        # Explicit, honest statement of what collection did and did not do.
        "executed": False,
        "verification_status": poc.verification_status,
    }
    log.info(
        "collected PoC %s sha256=%s class=%s lang=%s bytes=%d (not executed)",
        poc.poc_code,
        sha[:12],
        insp.safety_class.value,
        insp.language,
        len(data),
    )
    return _finish(result)
