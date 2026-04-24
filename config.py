from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # AlienVault OTX
    otx_api_key: str = ""

    # abuse.ch (ThreatFox + URLhaus) — one key covers both
    # Free at: https://abuse.ch/account (click "Get API key")
    abusech_api_key: str = ""

    # NVD
    nvd_api_key: str = ""

    # Anthropic — used by Claude AI News Collector (web search)
    # Free tier available at: https://console.anthropic.com
    anthropic_api_key: str = ""

    # Filtering — comma-separated sectors to track
    # Supported: banking, telecom, government (plus any custom sector for Claude AI collector)
    target_sectors: str = "banking,telecom,government"

    def get_target_sectors(self) -> List[str]:
        return [s.strip().lower() for s in self.target_sectors.split(",") if s.strip()]


settings = Settings()
