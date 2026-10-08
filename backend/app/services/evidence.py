"""Evidence engine.

Request/response pairs, screenshots, and raw tool output are captured for
findings. Small text evidence is stored inline in the DB; larger binary
artifacts go to MinIO object storage. If MinIO is unreachable the capture still
succeeds (inline-only) rather than losing the evidence.
"""

from __future__ import annotations

import hashlib
import io

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.finding import Evidence

log = get_logger("evidence")
_client = None
_bucket_ready = False


def _get_client():
    global _client
    if _client is None:
        from minio import Minio

        _client = Minio(
            f"{settings.minio_host}:{settings.minio_port}",
            access_key=settings.minio_root_user,
            secret_key=settings.minio_root_password,
            secure=settings.minio_secure,
        )
    return _client


def _ensure_bucket() -> bool:
    global _bucket_ready
    if _bucket_ready:
        return True
    try:
        c = _get_client()
        if not c.bucket_exists(settings.minio_bucket):
            c.make_bucket(settings.minio_bucket)
        _bucket_ready = True
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("MinIO unavailable, storing evidence inline only: %s", exc)
        return False


def put_artifact(key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    """Upload bytes to object storage; return the storage key or '' on failure."""
    if settings.queue_backend == "memory":  # tests / local in-proc: skip object storage
        return ""
    if not _ensure_bucket():
        return ""
    try:
        c = _get_client()
        c.put_object(
            settings.minio_bucket,
            key,
            io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )
        return key
    except Exception as exc:  # noqa: BLE001
        log.warning("evidence upload failed (%s); inline only", exc)
        return ""


def get_artifact(key: str) -> bytes | None:
    try:
        c = _get_client()
        resp = c.get_object(settings.minio_bucket, key)
        return resp.read()
    except Exception as exc:  # noqa: BLE001
        log.warning("evidence fetch failed for %s: %s", key, exc)
        return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def store(
    db: Session,
    *,
    target_id: str | None = None,
    scan_id: str | None = None,
    finding_id: str | None = None,
    kind: str = "request_response",
    scanner: str = "",
    request: str = "",
    response: str = "",
    http_status: int | None = None,
    headers: dict | None = None,
    body_excerpt: str = "",
    artifact: bytes | None = None,
    artifact_ext: str = "bin",
    content_type: str = "application/octet-stream",
    meta: dict | None = None,
) -> Evidence:
    storage_key = ""
    if artifact is not None:
        digest = sha256_hex(artifact)
        key = f"{target_id or 'misc'}/{scan_id or 'misc'}/{digest[:16]}.{artifact_ext}"
        storage_key = put_artifact(key, artifact, content_type)
        sha = digest
    else:
        sha = sha256_hex((request + response + body_excerpt).encode())

    ev = Evidence(
        target_id=target_id,
        scan_id=scan_id,
        finding_id=finding_id,
        kind=kind,
        scanner=scanner,
        request=request[:20000],
        response=response[:20000],
        http_status=http_status,
        headers=headers or {},
        body_excerpt=body_excerpt[:20000],
        storage_key=storage_key,
        sha256=sha,
        meta=meta or {},
    )
    db.add(ev)
    db.flush()
    return ev
