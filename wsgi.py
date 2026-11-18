"""
WSGI Entry Point for SSLGuard
Used by Gunicorn and other WSGI servers in production
"""

from app import app, db

# Create tables if they don't exist
with app.app_context():
    db.create_all()
    print("✓ Database tables created/verified")

# This is what Gunicorn will call
application = app

if __name__ == "__main__":
    # For local testing only
    app.run(debug=False, host='0.0.0.0', port=8000)
