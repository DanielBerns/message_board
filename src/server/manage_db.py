# manage_db.py
# This script is for offline database management tasks:
# 1. Initializing the database schema.
# 2. Creating the initial admin user.
# 3. Adding new client users.
import os
from getpass import getpass
from dotenv import load_dotenv

load_dotenv()

from app import create_app, db
from app.models import User
from app.extensions import bcrypt # For password hashing

# Create a minimal app context for DB operations
# This allows us to work with the database outside of a running Flask request
app = create_app(os.getenv('FLASK_CONFIG') or 'development')

def init_db():
    """Initializes the database and creates all tables."""
    with app.app_context():
        try:
            db.create_all()
            print("Database initialized and tables created successfully.")
        except Exception as e:
            print(f"Error initializing database: {e}")

def create_admin():
    """Creates the initial admin user if one doesn't exist."""
    with app.app_context():
        admin_username = input("Enter admin username: ")
        if User.query.filter_by(username=admin_username, is_admin=True).first():
            print(f"Admin user '{admin_username}' already exists.")
            return

        admin_password = getpass("Enter admin password: ")
        confirm_password = getpass("Confirm admin password: ")

        if admin_password != confirm_password:
            print("Passwords do not match. Admin user creation aborted.")
            return

        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin_user = User(username=admin_username, password_hash=hashed_password, is_admin=True)
        
        try:
            db.session.add(admin_user)
            db.session.commit()
            print(f"Admin user '{admin_username}' created successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {e}")

def add_client_user():
    """Adds a new client user to the database."""
    with app.app_context():
        client_username = input("Enter client username: ")
        if User.query.filter_by(username=client_username).first():
            print(f"User '{client_username}' already exists.")
            return

        client_password = getpass("Enter client password: ")
        confirm_password = getpass("Confirm client password: ")

        if client_password != confirm_password:
            print("Passwords do not match. Client user creation aborted.")
            return
        
        hashed_password = bcrypt.generate_password_hash(client_password).decode('utf-8')
        # Client users are not admins by default
        client_user = User(username=client_username, password_hash=hashed_password, is_admin=False)
        
        try:
            db.session.add(client_user)
            db.session.commit()
            print(f"Client user '{client_username}' created successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating client user: {e}")

if __name__ == '__main__':
    print("Database Management Script")
    print("--------------------------")
    while True:
        print("\nOptions:")
        print("1. Initialize Database (Create Tables)")
        print("2. Create Admin User")
        print("3. Add Client User")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            init_db()
        elif choice == '2':
            create_admin()
        elif choice == '3':
            add_client_user()
        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

