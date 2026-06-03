import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    PROJECT_NAME: str = "AI DevOps Copilot"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-for-ai-devops-copilot-1234567890")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 1 week

    # Database: Use PostgreSQL if configured, otherwise fallback to local SQLite for instant testing
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./devops_copilot.db")

    # API Keys
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")


settings = Settings()
