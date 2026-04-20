from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # AlienVault OTX
    otx_api_key: str = ""

    # NVD
    nvd_api_key: str = ""

    # XSIAM
    xsiam_base_url: str = ""
    xsiam_api_key: str = ""

    # Schedule (UTC)
    schedule_hour: int = 6
    schedule_minute: int = 0

    # Filtering
    target_sectors: str = "banking,finance,financial"

    @field_validator("xsiam_base_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    def get_target_sectors(self) -> List[str]:
        return [s.strip().lower() for s in self.target_sectors.split(",") if s.strip()]


settings = Settings()
