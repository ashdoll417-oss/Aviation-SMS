import os
from sqlalchemy import create_engine, text

def run_diagnostics():
    # 1. Get the database URL from the environment
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("CRITICAL ERROR: DATABASE_URL environment variable is not set!")
        return
        
    # Standardize the connection string for SQLAlchemy 2.0 if needed
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    engine = create_engine(db_url)
    
    print("\n=== STARTING DATABASE STRUCTURE DIAGNOSTICS ===")
    
    with engine.connect() as conn:
        # Check if the table even exists or has rows
        try:
            count_res = conn.execute(text("SELECT COUNT(*) FROM safety_assurance")).scalar()
            print(f"SUCCESS: 'safety_assurance' table exists. Total rows found in database: {count_res}")
        except Exception as e:
            print(f"FAILED: Could not read from safety_assurance table. Error: {e}")
            return

        # Check column names inside the database table right now
        try:
            print("\n--- Inspecting Database Schema Columns ---")
            columns_query = text("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'safety_assurance';
            """)
            cols = conn.execute(columns_query).fetchall()
            for col in cols:
                print(f"Column: {col[0]} | Type: {col[1]}")
        except Exception as e:
            print(f"FAILED to read schema columns: {e}")

        # Check the actual values of tenant_id and status inside the rows
        if count_res > 0:
            try:
                print("\n--- Sample Row Contents ---")
                sample_query = text("SELECT id, audit_scope, status, tenant_id FROM safety_assurance LIMIT 5")
                rows = conn.execute(sample_query).mappings().all()
                for r in rows:
                    print(f"Row ID: {r['id']} | Scope: {r['audit_scope']} | Status: {r['status']} | Tenant ID in DB: {r['tenant_id']!r}")
            except Exception as e:
                print(f"FAILED to read sample rows: {e}")
                
    print("=== END OF DIAGNOSTICS ===\n")

if __name__ == "__main__":
    run_diagnostics()
