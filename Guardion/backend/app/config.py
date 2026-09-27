"""
Guardion Configuration
Loads environment variables and defines app-wide settings.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # ==========================================
    # GEMINI AI
    # ==========================================

    GEMINI_API_KEY: str = os.getenv(
        "GEMINI_API_KEY",
        ""
    )

    # Primary Gemini model
    GEMINI_MODEL: str = os.getenv(
        "GEMINI_MODEL",
        "gemini-3.8-flash"
    )

    # Fallback model chain
    GEMINI_FALLBACK_MODELS: list[str] = [
        model.strip()
        for model in os.getenv(
            "GEMINI_FALLBACK_MODELS",
            "gemini-3.8-flash,gemini-flash-lite-latest,gemini-flash-latest"
        ).split(",")
        if model.strip()
    ]

    # Economy mode
    ECONOMY_MODE: bool = os.getenv(
        "ECONOMY_MODE",
        "true"
    ).lower() in ("true", "1", "yes")

    # Maximum Gemini calls per minute
    GEMINI_RPM_LIMIT: int = int(
        os.getenv(
            "GEMINI_RPM_LIMIT",
            "10"
        )
    )

    # ==========================================
    # SERVER
    # ==========================================

    HOST: str = os.getenv(
        "HOST",
        "0.0.0.0"
    )

    PORT: int = int(
        os.getenv(
            "PORT",
            "8000"
        )
    )

    # ==========================================
    # CORS
    # ==========================================

    CORS_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://localhost:5173,chrome-extension://*"
        ).split(",")
        if origin.strip()
    ]

    # ==========================================
    # TEMP DIRECTORY
    # ==========================================

    TEMP_DIR: str = os.getenv(
        "TEMP_DIR",
        "./tmp_repos"
    )

    # ==========================================
    # OSV API
    # ==========================================

    OSV_API_URL: str = "https://api.osv.dev/v1/query"

    # ==========================================
    # NVD API
    # ==========================================

    NVD_API_KEY: str = os.getenv(
        "NVD_API_KEY",
        ""
    )

    # ==========================================
    # MONGODB
    # ==========================================

    MONGO_URI: str = os.getenv(
        "MONGO_URI",
        "mongodb://localhost:27017"
    )

    MONGO_DB_NAME: str = os.getenv(
        "MONGO_DB_NAME",
        "guardion"
    )

    # ==========================================
    # JWT AUTHENTICATION
    # ==========================================

    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "guardion-super-secret-key-change-in-production"
    )

    JWT_ALGORITHM: str = os.getenv(
        "JWT_ALGORITHM",
        "HS256"
    )

    JWT_EXPIRE_MINUTES: int = int(
        os.getenv(
            "JWT_EXPIRE_MINUTES",
            "1440"
        )
    )


# ==========================================
# SETTINGS INSTANCE
# ==========================================

settings = Settings()