"""Application configuration.

All runtime settings are read from environment variables (or a local `.env`
file) via pydantic-settings. Centralising config here keeps secrets and
deployment-specific values out of the codebase, which is what lets us swap
SQLite -> Postgres or local SonarQube -> a remote one without touching code.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed application settings.

    Pydantic validates and coerces these values at startup, so a missing or
    malformed setting fails fast instead of surfacing as a confusing runtime
    error later.
    """

    # --- Core ---------------------------------------------------------------
    app_name: str = "SecureLens"
    debug: bool = False

    # --- Database -----------------------------------------------------------
    # SQLite locally; swap to a postgresql:// URL on EC2 without code changes.
    database_url: str = "sqlite:///./securelens.db"

    # --- LLM (Groq) ---------------------------------------------------------
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    # --- SonarQube ----------------------------------------------------------
    sonarqube_host: str = "http://localhost:9000"
    sonarqube_token: str = ""

    # --- RAG (ChromaDB + Ollama embeddings) ---------------------------------
    chroma_dir: str = "./chroma"
    chroma_collection: str = "securelens_kb"
    knowledge_base_dir: str = "./knowledge_base"
    ollama_base_url: str = "http://localhost:11434"
    embedding_model: str = "nomic-embed-text"

    # --- Auth (JWT) ---------------------------------------------------------
    jwt_secret: str = "change-me-in-prod"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance.

    Caching means the .env file is parsed once per process and the same object
    is reused everywhere (including as a FastAPI dependency), avoiding repeated
    disk reads and giving us a single source of truth.
    """
    return Settings()
