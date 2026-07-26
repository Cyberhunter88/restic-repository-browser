from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RRB_", env_file=".env", extra="ignore")

    data_dir: Path = Path("./data")
    repository_root: Path = Path("./repositories")
    database_url: str | None = None
    initial_admin_password: str = ""
    http_port: int = Field(default=8080, ge=1, le=65535)
    tls_mode: str = Field(default="proxy", pattern=r"^(proxy|files)$")
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    trusted_proxy_ips: str = "127.0.0.1,::1"
    frontend_dir: Path = Path("frontend/dist")
    session_cookie_name: str = "rrb_session"
    session_ttl_seconds: int = Field(default=86400, ge=900, le=2592000)
    session_idle_seconds: int = Field(default=3600, ge=300, le=86400)
    snapshot_cache_seconds: int = Field(default=300, ge=30, le=86400)
    max_parallel_restic: int = Field(default=2, ge=1, le=16)
    login_retention_days: int = Field(default=30, ge=1, le=3650)
    job_retention_days: int = Field(default=30, ge=1, le=3650)
    audit_retention_days: int = Field(default=90, ge=1, le=3650)
    refresh_job_lease_seconds: int = Field(default=60, ge=15, le=3600)
    worker_poll_seconds: float = Field(default=1.0, ge=0.1, le=60)
    allowed_remote_targets: str = ""

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'browser.db').as_posix()}"

    @property
    def master_key_path(self) -> Path:
        return self.data_dir / "security" / "master.key"

    @property
    def restic_cache_dir(self) -> Path:
        return self.data_dir / "cache"

    def is_trusted_proxy(self, value: str) -> bool:
        try:
            address = ip_address(value)
        except ValueError:
            return False
        for item in (part.strip() for part in self.trusted_proxy_ips.split(",")):
            if not item:
                continue
            try:
                if address in ip_network(item, strict=False):
                    return True
            except ValueError:
                continue
        return False


@lru_cache
def get_settings() -> Settings:
    return Settings()
