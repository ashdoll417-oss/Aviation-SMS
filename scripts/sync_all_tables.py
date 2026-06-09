import os
from app import create_app, db
import models

# Ensure we pull the correct production database URL
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app = create_app()
with app.app_context():
    print("Syncing database tables...")
    db.create_all()
    print("All tables synced successfully (including risk_assessment)!")
