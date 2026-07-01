# =============================================================================
# HexShield AI — Application Configuration
# Reads all settings from the .env file using pydantic-settings.
# This is the single source of truth for configuration across the entire
# backend application.
# =============================================================================

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List
import os


class Settings(BaseSettings):
    """
    Central configuration class for HexShield AI backend.
    All values are loaded from the .env file automatically.
    """

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "HexShield AI"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_ECHO: bool = False

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # -------------------------------------------------------------------------
    # File Storage
    # -------------------------------------------------------------------------
    UPLOAD_DIR: str = "storage/uploads"
    REPORTS_DIR: str = "storage/reports"
    MAX_UPLOAD_SIZE_MB: int = 500

    # -------------------------------------------------------------------------
    # Layer 1 — Hex Triage Engine
    # -------------------------------------------------------------------------
    ENTROPY_ELEVATED_THRESHOLD: float = 6.5
    ENTROPY_CRITICAL_THRESHOLD: float = 7.2
    MAGIC_BYTES_READ_LENGTH: int = 32

    # -------------------------------------------------------------------------
    # Layer 2 — AI Media Engine
    # -------------------------------------------------------------------------
    AI_MODEL_WEIGHTS_DIR: str = "app/services/ai_engine/weights"
    AI_CONFIDENCE_THRESHOLD: float = 0.75
    AI_INFERENCE_DEVICE: str = "cpu"
    HUGGINGFACE_API_TOKEN: str = ""

    # -------------------------------------------------------------------------
    # Layer 3 — Forensic Reporting
    # -------------------------------------------------------------------------
    REPORT_ISSUING_AUTHORITY: str = "HexShield AI Forensic Platform"
    REPORT_JURISDICTION: str = "Republic of Kenya"
    CHAIN_OF_CUSTODY_STRICT_MODE: bool = True

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/hexshield.log"

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------
    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        allowed = {"development", "staging", "production"}
        if value not in allowed:
            raise ValueError(f"APP_ENV must be one of: {allowed}")
        return value

    @field_validator("AI_INFERENCE_DEVICE")
    @classmethod
    def validate_inference_device(cls, value: str) -> str:
        allowed = {"cpu", "cuda:0", "cuda:1", "mps"}
        if value not in allowed:
            raise ValueError(f"AI_INFERENCE_DEVICE must be one of: {allowed}")
        return value

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long.")
        return value

    # -------------------------------------------------------------------------
    # Computed Properties
    # -------------------------------------------------------------------------
    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse comma-separated ALLOWED_ORIGINS into a Python list."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]

    @property
    def max_upload_size_bytes(self) -> int:
        """Convert MAX_UPLOAD_SIZE_MB to bytes for file validation."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


# =============================================================================
# Global settings instance
# Import this object anywhere in the application:
#   from app.config import settings
# =============================================================================
settings = Settings()


# =============================================================================
# Storage directory bootstrap
# Ensures required directories exist when the application starts.
# =============================================================================
def ensure_storage_dirs() -> None:
    """
    Create storage directories if they do not exist.
    Called once at application startup.
    """
    dirs = [
        settings.UPLOAD_DIR,
        settings.REPORTS_DIR,
        "logs",
    ]
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)