import sys
from sqlalchemy import create_engine, text

DB_URL = "postgresql://postgres.dzzzkstaepbixcusysoc:m4FhWYIUv5hO17Qv@aws-1-eu-central-1.pooler.supabase.com:6543/postgres"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS login_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'success'
);
"""

def main() -> None:
    engine = create_engine(DB_URL, pool_pre_ping=True)
    with engine.connect() as conn:
        conn.execute(text(CREATE_TABLE_SQL))
        conn.commit()
    print("DDL Execution complete: 'login_log' table successfully created on Supabase.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"DDL execution failed: {e}", file=sys.stderr)
        raise
