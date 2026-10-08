"""Application configuration.

All settings come from environment variables (or a .env file in development).
Secrets are never hard-coded; production refuses to start with insecure defaults.
"""

from __future__ import annotations

import functools
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Scan intensity ordering (used to clamp per-target profiles to a global ceiling).
INTENSITY_ORDER = ["passive", "safe", "standard", "aggressive"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # --- core ---
    env: str = Field("production", alias="WPSEC_ENV")
    log_level: str = Field("INFO", alias="WPSEC_LOG_LEVEL")
    public_url: str = Field("https://localhost", alias="WPSEC_PUBLIC_URL")

    secret_key: str = Field(
        "dev-insecure-secret-change-me-in-production-only", alias="WPSEC_SECRET_KEY"
    )
    credential_key: str = Field("", alias="WPSEC_CREDENTIAL_KEY")

    access_token_minutes: int = Field(30, alias="WPSEC_ACCESS_TOKEN_MINUTES")
    refresh_token_days: int = Field(7, alias="WPSEC_REFRESH_TOKEN_DAYS")

    # Global safety ceiling on scan intensity, regardless of per-target profile.
    max_intensity: str = Field("standard", alias="WPSEC_MAX_INTENSITY")

    # --- database ---
    database_url_override: str = Field("", alias="WPSEC_DATABASE_URL")
    postgres_user: str = Field("wpsec", alias="POSTGRES_USER")
    postgres_password: str = Field("wpsec", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field("wpsec", alias="POSTGRES_DB")
    postgres_host: str = Field("postgres", alias="POSTGRES_HOST")
    postgres_port: int = Field(5432, alias="POSTGRES_PORT")

    # --- redis / queue ---
    redis_host: str = Field("redis", alias="REDIS_HOST")
    redis_port: int = Field(6379, alias="REDIS_PORT")
    redis_password: str = Field("", alias="REDIS_PASSWORD")
    queue_backend_override: str = Field("", alias="WPSEC_QUEUE_BACKEND")  # "" | redis | memory

    # --- object storage ---
    minio_host: str = Field("minio", alias="MINIO_HOST")
    minio_port: int = Field(9000, alias="MINIO_PORT")
    minio_root_user: str = Field("wpsec", alias="MINIO_ROOT_USER")
    minio_root_password: str = Field("wpsec", alias="MINIO_ROOT_PASSWORD")
    minio_bucket: str = Field("wpsec-evidence", alias="MINIO_BUCKET")
    minio_secure: bool = Field(False, alias="MINIO_SECURE")

    # --- initial admin ---
    admin_email: str = Field("admin@example.com", alias="WPSEC_ADMIN_EMAIL")
    admin_password: str = Field("", alias="WPSEC_ADMIN_PASSWORD")

    # --- worker ---
    worker_name: str = Field("worker", alias="WPSEC_WORKER_NAME")
    worker_queues: str = Field("default", alias="WPSEC_WORKER_QUEUES")
    worker_concurrency: int = Field(2, alias="WPSEC_WORKER_CONCURRENCY")

    # --- scanner engines ---
    zap_host: str = Field("zap", alias="ZAP_HOST")
    zap_port: int = Field(8090, alias="ZAP_PORT")
    wpscan_api_token: str = Field("", alias="WPSCAN_API_TOKEN")
    nvd_api_key: str = Field("", alias="NVD_API_KEY")

    # Static analysis (Semgrep) source root, content-discovery (ffuf) wordlist.
    source_dir: str = Field("", alias="WPSEC_SOURCE_DIR")
    ffuf_wordlist: str = Field("", alias="WPSEC_FFUF_WORDLIST")

    # Optional, operator-provided Burp Suite REST API (commercial). OWASP ZAP is
    # the free default already integrated; leave blank to use ZAP only.
    burp_api_url: str = Field("", alias="BURP_API_URL")
    burp_api_key: str = Field("", alias="BURP_API_KEY")

    # One-click Full Audit: auto-generate a report when a scan finishes.
    auto_report_format: str = Field("html", alias="WPSEC_AUTO_REPORT_FORMAT")

    # ------------------------------------------------------------------ helpers
    @property
    def is_production(self) -> bool:
        return self.env.lower() in ("production", "prod")

    @property
    def is_test(self) -> bool:
        return self.env.lower() in ("test", "testing")

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        if self.is_test:
            # Shared in-memory DB for the whole test process.
            return "sqlite+pysqlite://"
        if not self.is_production:
            # Local dev convenience: a file-backed SQLite DB in the backend dir.
            p = Path(__file__).resolve().parents[2] / "wpsec-dev.db"
            return f"sqlite+pysqlite:///{p}"
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def redis_url(self) -> str:
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/0"

    @property
    def queue_backend(self) -> str:
        if self.queue_backend_override:
            return self.queue_backend_override
        return "memory" if self.is_test else "redis"

    @property
    def worker_queue_list(self) -> list[str]:
        return [q.strip() for q in self.worker_queues.split(",") if q.strip()]

    @property
    def max_intensity_rank(self) -> int:
        try:
            return INTENSITY_ORDER.index(self.max_intensity.lower())
        except ValueError:
            return INTENSITY_ORDER.index("standard")

    def clamp_intensity(self, requested: str) -> str:
        """Clamp a requested intensity to the global ceiling."""
        try:
            r = INTENSITY_ORDER.index(requested.lower())
        except ValueError:
            r = INTENSITY_ORDER.index("safe")
        return INTENSITY_ORDER[min(r, self.max_intensity_rank)]

    def validate_runtime(self) -> list[str]:
        """Return a list of production misconfigurations (empty == OK)."""
        problems: list[str] = []
        if self.is_production:
            if "insecure" in self.secret_key or len(self.secret_key) < 32:
                problems.append("WPSEC_SECRET_KEY is weak or default")
            if not self.credential_key:
                problems.append("WPSEC_CREDENTIAL_KEY is required in production")
            if self.postgres_password in ("", "wpsec", "change-me-run-install-sh"):
                problems.append("POSTGRES_PASSWORD is default/empty")
        return problems


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
