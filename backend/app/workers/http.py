"""HTTP client used by scanner steps.

TLS verification is disabled for *target* traffic (security scanners routinely
test hosts with self-signed or mismatched certificates); certificate details are
captured separately rather than causing false negatives. This does not affect
the platform's own outbound calls.

Tests inject a transport via :func:`set_transport_for_tests` so the pipeline can
run without real network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

_TEST_TRANSPORT: httpx.BaseTransport | None = None
DEFAULT_TIMEOUT = 15.0
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
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        **kwargs,
    )


def fetch(url: str, method: str = "GET", **kwargs) -> Resp:
    try:
        with _client() as c:
            r = c.request(method, url, **kwargs)
            body = r.text if len(r.content) < 2_000_000 else r.text[:2_000_000]
            return Resp(
                url=str(r.url),
                status_code=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                text=body,
            )
    except httpx.HTTPError as exc:
        return Resp(url=url, status_code=0, error=f"{type(exc).__name__}: {exc}")
