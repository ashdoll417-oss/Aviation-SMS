import os
import sys

# Ensure repo root is on sys.path so `import app` works when running this script.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from app import create_app, db
import models

db_url = "postgresql://postgres.dzzzkstaepbixcusysoc:m4FhWYIUv5hO17Qv@aws-1-eu-central-1.pooler.supabase.com:6543/postgres"
os.environ["DATABASE_URL"] = db_url

app = create_app()
with app.app_context():
    print("Synchronizing all application tables with live Supabase cluster...")
    db.create_all()
    print("SUCCESS: All database tables are fully built and synchronized!")
