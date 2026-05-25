import os

class Config:
    # Fail fast on Vercel if SECRET_KEY is not provided.
    # Using a dev fallback in production can break session security guarantees.
    if os.environ.get("VERCEL"):
        SECRET_KEY = os.environ.get("SECRET_KEY")
        if not SECRET_KEY:
            raise RuntimeError("SECRET_KEY is required in production (Vercel) but was not found.")
    else:
        SECRET_KEY = os.environ.get("SECRET_KEY", "dev_session_fallback_key")

    # Fetch database URL from environment variables
    raw_db_url = os.environ.get("DATABASE_URL")

    # On Vercel we must fail fast if DATABASE_URL is missing; falling back to SQLite
    # can cause confusing production 500/OperationalError failures.
    if os.environ.get("VERCEL") and not raw_db_url:
        raise RuntimeError("DATABASE_URL is required in production (Vercel) but was not found.")

    if raw_db_url:
        # Repair legacy dialect prefixes if present
        if raw_db_url.startswith("postgres://"):
            raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = raw_db_url
    else:
        # Fallback for local desktop offline development only
        SQLALCHEMY_DATABASE_URI = "sqlite:///local_dev.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # SQLAlchemy engine hardening for serverless/transient DB connectivity (Supabase pooler)
    # Note: For psycopg2, sslmode is best enforced via the DATABASE_URL/DSN (or handled by the pooler),
    # not via connect_args, which can break depending on driver expectations.
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # File upload configuration
