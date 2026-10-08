"""Redis client + a small, transparent job queue.

The queue is intentionally simple (Redis lists with reliable BRPOPLPUSH-style
handling) rather than pulling in Celery/RQ, so the orchestration is easy to
audit. A pure in-process backend is used for tests.
"""

from __future__ import annotations

import collections
import json
import threading
import time
from typing import Any

import redis as redis_lib

from app.core.config import settings

_redis_client: redis_lib.Redis | None = None


def get_redis() -> redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(
            settings.redis_url, decode_responses=True, socket_connect_timeout=5
        )
    return _redis_client


# --------------------------------------------------------------------- queues
QUEUE_PREFIX = "wpsec:q:"


class BaseJobQueue:
    def enqueue(self, queue: str, job: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

    def dequeue(
        self, queues: list[str], timeout: int = 5
    ) -> dict[str, Any] | None:  # pragma: no cover
        raise NotImplementedError

    def size(self, queue: str) -> int:  # pragma: no cover
        raise NotImplementedError


class RedisJobQueue(BaseJobQueue):
    def __init__(self) -> None:
        self.r = get_redis()

    def enqueue(self, queue: str, job: dict[str, Any]) -> None:
        self.r.lpush(QUEUE_PREFIX + queue, json.dumps(job))

    def dequeue(self, queues: list[str], timeout: int = 5) -> dict[str, Any] | None:
        keys = [QUEUE_PREFIX + q for q in queues]
        res = self.r.brpop(keys, timeout=timeout)
        if res is None:
            return None
        _key, raw = res
        return json.loads(raw)

    def size(self, queue: str) -> int:
        return int(self.r.llen(QUEUE_PREFIX + queue))


class MemoryJobQueue(BaseJobQueue):
    """In-process queue for tests and single-process dev runs."""

    def __init__(self) -> None:
        self._queues: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def enqueue(self, queue: str, job: dict[str, Any]) -> None:
        with self._lock:
            self._queues[queue].append(json.loads(json.dumps(job)))

    def dequeue(self, queues: list[str], timeout: int = 5) -> dict[str, Any] | None:
        deadline = time.time() + timeout
        while True:
            with self._lock:
                for q in queues:
                    if self._queues[q]:
                        return self._queues[q].popleft()
            if time.time() >= deadline:
                return None
            time.sleep(0.05)

    def size(self, queue: str) -> int:
        with self._lock:
            return len(self._queues[queue])


_queue: BaseJobQueue | None = None


def get_queue() -> BaseJobQueue:
    global _queue
    if _queue is None:
        _queue = MemoryJobQueue() if settings.queue_backend == "memory" else RedisJobQueue()
    return _queue


def reset_queue_for_tests() -> None:
    global _queue
    _queue = MemoryJobQueue()
