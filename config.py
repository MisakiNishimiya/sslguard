"""
SSLGuard Configuration
Stores database path, secret key, and SMTP settings.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file (if it exists)
load_dotenv()

# Flask Configuration
FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# Flask secret key for session management
SECRET_KEY = os.environ.get('SSLGUARD_SECRET_KEY', 'dev-secret-key-change-in-production')

# Warn if using default secret key in production
if SECRET_KEY == 'dev-secret-key-change-in-production' and FLASK_ENV == 'production':
    print("⚠️  WARNING: Using default SECRET_KEY in production! Set SSLGUARD_SECRET_KEY environment variable.")

# Database Configuration
# Use DATABASE_URL from environment (Railway/Render provide this)
# Falls back to SQLite for local development
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # Fix postgres:// to postgresql:// (Railway uses old format)
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
else:
    # SQLite for local development
    SQLALCHEMY_DATABASE_URI = 'sqlite:///sslguard.db'

SQLALCHEMY_TRACK_MODIFICATIONS = False

# SMTP Configuration - read from environment variables
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SMTP_FROM_EMAIL = os.environ.get('SMTP_FROM_EMAIL', '')

# Email alert thresholds (in days before expiry)
ALERT_THRESHOLDS = [30, 14, 7, 1]

# Certificate status thresholds (in days before expiry)
STATUS_CRITICAL_DAYS = 7    # Critical: <=7 days until expiry
STATUS_WARNING_DAYS = 30    # Warning: 8-30 days until expiry

# Scan configuration
SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 10))  # seconds
DAILY_SCAN_HOUR = 2  # 2 AM UTC
