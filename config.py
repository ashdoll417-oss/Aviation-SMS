import os

class Config:
    # SQLite database URI
    SQLALCHEMY_DATABASE_URI = 'sqlite:///aviation_sms_erp.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'aviation-sms-erp-dev-secret-key-2024'
    
    # File upload configuration
