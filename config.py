import os

class Config:
    # Secret key: allow Vercel/prod to provide SECRET_KEY, keep safe fallback for local dev
    SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secure_fallback_local_key")

    # Use Supabase PostgreSQL URI if available in production.
    # Vercel sometimes provides a `postgres://` URL; SQLAlchemy expects `postgresql://`.
    raw_db_url = os.environ.get("DATABASE_URL")
    if raw_db_url and raw_db_url.startswith("postgres://"):
        raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = raw_db_url or "sqlite:///instance/local_dev.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload configuration
