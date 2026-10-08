"""HTTP client used by scanner steps.

TLS verification is disabled for *target* traffic (security scanners routinely
test hosts with self-signed or mismatched certificates); certificate details are
captured separately rather than causing false negatives. This does not affect
the platform's own outbound calls.

Redirects are followed MANUALLY and every hop is validated against the
authorization scope (see app.workers.netguard), so a target cannot redirect the
scanner to cloud metadata / loopback / an out-of-scope host (SSRF + scope
escape). Response bodies are read with a hard size cap to bound memory.

Tests inject a transport via :func:`set_transport_for_tests` so the pipeline can
run without real network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.workers import netguard

_TEST_TRANSPORT: httpx.BaseTransport | None = None
DEFAULT_TIMEOUT = 15.0
MAX_BODY_BYTES = 3_000_000
MAX_REDIRECTS = 5
USER_AGENT = "wp-audit-win/0.1 (authorized security assessment)"


def set_transport_for_tests(transport: httpx.BaseTransport | None) -> None:
    global _TEST_TRANSPORT
    _TEST_TRANSPORT = transport


@dataclass
class Resp:
    url: str
    status_code: int
    headers: dict = field(default_factory=dict)
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and 0 < self.status_code < 600


def _client(**kwargs) -> httpx.Client:
    return httpx.Client(
        transport=_TEST_TRANSPORT,
        verify=False if _TEST_TRANSPORT is None else True,  # target traffic only
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,  # we follow manually with per-hop scope checks
        headers={"User-Agent": USER_AGENT},
        **kwargs,
    )


def _read_body(resp: httpx.Response) -> str:
    try:
        raw = resp.content  # httpx buffers; cap what we keep
    except Exception:  # noqa: BLE001
        return ""
    if len(raw) > MAX_BODY_BYTES:
        raw = raw[:MAX_BODY_BYTES]
    try:
        return raw.decode(resp.encoding or "utf-8", errors="replace")
    except (LookupError, TypeError):
        return raw.decode("utf-8", errors="replace")


def fetch(
    url: str,
    method: str = "GET",
    *,
    scope: list[str] | None = None,
    **kwargs,
) -> Resp:
    """Fetch a URL, following redirects manually while enforcing the scope.

    ``scope`` is the authorization's allowed scope; when provided, every hop
    (initial + each redirect) must be in scope or the fetch is refused.
    """
    allowed, reason = netguard.url_allowed(url, scope or [])
    if not allowed:
        return Resp(url=url, status_code=0, error=f"blocked by scope guard: {reason}")

    current = url
    try:
        with _client() as c:
            for _ in range(MAX_REDIRECTS + 1):
                r = c.request(method, current, **kwargs)
                if r.is_redirect and r.headers.get("location"):
                    nxt = (
                        str(r.next_request.url)
                        if r.next_request
                        else urljoin(current, r.headers["location"])
                    )
                    ok, why = netguard.url_allowed(nxt, scope or [])
                    if not ok:
                        return Resp(
                            url=current,
                            status_code=r.status_code,
                            headers={k.lower(): v for k, v in r.headers.items()},
                            error=f"redirect blocked by scope guard: {why} ({nxt})",
                        )
                    current = nxt
                    method = "GET" if r.status_code in (301, 302, 303) else method
                    continue
                return Resp(
                    url=str(r.url),
                    status_code=r.status_code,
                    headers={k.lower(): v for k, v in r.headers.items()},
                    text=_read_body(r),
                )
            return Resp(url=current, status_code=0, error="too many redirects")
    except httpx.HTTPError as exc:
        return Resp(url=current, status_code=0, error=f"{type(exc).__name__}: {exc}")
