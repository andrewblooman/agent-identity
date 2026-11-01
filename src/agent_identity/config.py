"""Settings, read from environment variables and .env."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    default_view: str = "demo"
    aws_profile: str | None = None
    scan_regions: Annotated[list[str], NoDecode] = ["eu-west-1"]
    cloudtrail_lookback_days: int = 14
    trivy_enabled: bool = True
    trivy_timeout_seconds: int = 300
    max_images_to_scan: int = 20
    database_path: Path = Path("data/agent_identity.sqlite3")
    allowed_hosts: Annotated[list[str], NoDecode] = ["localhost", "127.0.0.1", "testserver"]

    @field_validator("scan_regions", "allowed_hosts", mode="before")
    @classmethod
    def _split(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


def get_settings() -> Settings:
    return Settings()
