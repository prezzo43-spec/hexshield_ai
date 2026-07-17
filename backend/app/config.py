# =============================================================================
# HexShield AI — Application Configuration
# Reads all settings from the .env file using pydantic-settings.
# This is the single source of truth for configuration across the entire
# backend application.
# =============================================================================

from pathlib import Path
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
    ALLOWED_UPLOAD_EXTENSIONS: str = ".jpg,.jpeg,.png,.bmp,.webp,.tiff,.tif,.pdf,.txt,.json,.csv,.log,.mp4,.mov,.avi,.wav,.mp3,.flac,.docx,.doc"
    ALLOWED_UPLOAD_MIME_PREFIXES: str = "image/,video/,audio/,application/pdf,application/msword,application/vnd.openxmlformats-officedocument,text/,application/json,application/csv,application/octet-stream"

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
    GROQ_API_KEY: str = ""

    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    ALLOWED_MODEL_WEIGHTS_HASHES: str = ""
    MODEL_WEIGHTS_PUBLIC_KEY_PATH: str = "app/services/ai_engine/weights/model_weights_pubkey.pem"
    MODEL_WEIGHTS_SIGNATURE_EXTENSION: str = ".sig"
    MAX_REQUEST_BODY_SIZE_MB: int = 520
    MAX_FORM_FIELDS: int = 100

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
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def allowed_hosts_list(self) -> List[str]:
        """Parse comma-separated ALLOWED_HOSTS into a Python list."""
        return [host.strip() for host in self.ALLOWED_HOSTS.split(",") if host.strip()]

    @property
    def allowed_model_weights_hashes(self) -> List[str]:
        """Parse comma-separated trusted model weight hashes."""
        return [hash_value.strip() for hash_value in self.ALLOWED_MODEL_WEIGHTS_HASHES.split(",") if hash_value.strip()]

    @property
    def allowed_upload_extensions(self) -> List[str]:
        """Parse comma-separated allowed upload file extensions."""
        return [ext.strip().lower() for ext in self.ALLOWED_UPLOAD_EXTENSIONS.split(",") if ext.strip()]

    @property
    def allowed_upload_mime_prefixes(self) -> List[str]:
        """Parse comma-separated allowed upload MIME type prefixes."""
        return [mime.strip().lower() for mime in self.ALLOWED_UPLOAD_MIME_PREFIXES.split(",") if mime.strip()]

    @property
    def model_weights_public_key_path(self) -> Path:
        """Path to the trusted public key used for verifying model weights."""
        return Path(self.MODEL_WEIGHTS_PUBLIC_KEY_PATH)

    @property
    def model_weights_signature_extension(self) -> str:
        """File extension expected for model weight signature files."""
        return self.MODEL_WEIGHTS_SIGNATURE_EXTENSION

    @property
    def max_upload_size_bytes(self) -> int:
        """Convert MAX_UPLOAD_SIZE_MB to bytes for file validation."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def max_request_body_size_bytes(self) -> int:
        """Convert MAX_REQUEST_BODY_SIZE_MB to bytes for request validation."""
        return self.MAX_REQUEST_BODY_SIZE_MB * 1024 * 1024

    @property
    def max_form_fields(self) -> int:
        """Maximum allowed form fields in a single request."""
        return self.MAX_FORM_FIELDS

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