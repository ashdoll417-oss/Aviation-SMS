import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_session_fallback_key")

    # Fetch database URL from environment variables
    raw_db_url = os.environ.get("DATABASE_URL")

    if raw_db_url:
        # Repair legacy dialect prefixes if present
        if raw_db_url.startswith("postgres://"):
            raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = raw_db_url
    else:
        # Fallback for local desktop offline development only
        SQLALCHEMY_DATABASE_URI = "sqlite:///local_dev.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload configuration
