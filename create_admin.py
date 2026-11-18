"""
Create the first administrator user for SSLGuard.
Run this once after initial setup.
"""

from app import app, db
from models import User


def create_admin():
    """Create admin user from command line input"""
    with app.app_context():
        print("=" * 50)
        print("Create Administrator User")
        print("=" * 50)
        
        # Check if admin already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            print("An administrator already exists.")
            return
        
        while True:
            username = input("Enter username: ").strip()
            if not username:
                print("Username cannot be empty.")
                continue
            
            # Check if username exists
            existing = User.query.filter_by(username=username).first()
            if existing:
                print("Username already exists.")
                continue
            
            break
        
        while True:
            password = input("Enter password (min 6 characters): ").strip()
            if len(password) < 6:
                print("Password must be at least 6 characters.")
                continue
            
            confirm = input("Confirm password: ").strip()
            if password != confirm:
                print("Passwords do not match.")
                continue
            
            break
        
        # Create admin user
        admin = User(username=username, role='admin')
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        
        print(f"✓ Administrator '{username}' created successfully!")


if __name__ == '__main__':
    create_admin()
