from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # CORS Settings
    CORS_ORIGINS: list[str] = Field(default_factory=lambda: ["*"])
    CORS_METHODS: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    )
    CORS_HEADERS: list[str] = Field(default_factory=lambda: ["*"])
    CORS_CREDENTIALS: bool = True
    API_KEY: str = Field(..., env="API_KEY")
    PREFIX: str
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"

class LLMSettings(Settings):
    OPENAI_MODEL_NAME: str
    OPENAI_API_KEY: str
    OPENAI_BASE_URL: str


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

@lru_cache
def get_llm_settings() -> LLMSettings:
    """Get cached LLM settings instance."""
    return LLMSettings()
