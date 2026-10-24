import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "AgentShieldAI"
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./agentshieldai.db"
    
    # Google Gemini Settings
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-flash"
    
    # CORS & Security
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    AUTH_SECRET_KEY: str = "default_agentshield_secret_key_needs_override_in_prod"
    AUTH_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    
    # File handling
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: str = ".txt,.pdf,.csv,.md,.json"
    UPLOAD_DIR: str = "./uploads"

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def allowed_origins(self) -> List[str]:
        origins = [self.FRONTEND_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"]
        return list(set(filter(None, origins)))

    @property
    def allowed_file_extensions(self) -> List[str]:
        return [ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",")]


settings = Settings()
