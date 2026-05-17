"""
core/config.py
Application configuration loaded from environment variables / .env file.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Dependency Risk Radar"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # API Keys
    ANTHROPIC_API_KEY: str = ""
    NVD_API_KEY: str = ""        # optional — increases NVD rate limit
    GEMINI_API_KEY: str = ""     # Google Gemini — takes priority over Anthropic if set
    GEMINI_MODEL: str = "gemini-1.5-flash"

    # Database
    DATABASE_URL: str = "sqlite:///./drr.db"

    # Redis (optional)
    REDIS_URL: str = ""

    # Scoring weights (must sum to 1.0)
    WEIGHT_CVE: float = 0.45
    WEIGHT_OBSOLESCENCE: float = 0.25
    WEIGHT_LICENCE: float = 0.20
    WEIGHT_TRACKER: float = 0.10

    # Risk thresholds
    THRESHOLD_CRITICAL: float = 75.0
    THRESHOLD_HIGH: float = 50.0
    THRESHOLD_MODERATE: float = 20.0

    # External API URLs
    OSV_API_URL: str = "https://api.osv.dev/v1"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAVEN_SEARCH_URL: str = "https://search.maven.org/solrsearch/select"
    EXODUS_API_URL: str = "https://reports.exodus-privacy.eu.org/api/trackers"
    CLEARLY_DEFINED_URL: str = "https://api.clearlydefined.io/definitions"

    # LLM
    LLM_MODEL: str = "claude-sonnet-4-20250514"
    LLM_MAX_TOKENS: int = 4096
    LLM_TIMEOUT: int = 60

    # Analysis limits
    MAX_COMPONENTS_FOR_LLM: int = 30
    HTTP_TIMEOUT: float = 15.0
    MAX_CONCURRENT_API_CALLS: int = 10

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
