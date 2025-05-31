# run.py
# This file is used to run the Flask development server.
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app import create_app

# Create the Flask app instance using the app factory
# It will look for FLASK_CONFIG in environment variables, defaulting to 'development'
config_name = os.getenv('FLASK_CONFIG', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Run the app
    # Host '0.0.0.0' makes the server accessible externally
    # Debug mode should be False in production
    app.run(host='0.0.0.0', port=5000, debug=app.config.get('DEBUG', False))

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

# app/__init__.py
# This file contains the application factory function `create_app`.
# It initializes the Flask app, configures it, initializes extensions, and registers blueprints.
import os
from flask import Flask
from .config import config
from .extensions import db, bcrypt, jwt, migrate # Added migrate
from .models import User # Ensure models are imported so SQLAlchemy knows about them

def create_app(config_name=None):
    """
    Application factory function.
    Creates and configures the Flask application.
    """
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')

    app = Flask(__name__)
    app.config.from_object(config[config_name]) # Load configuration

    # Initialize Flask extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db) # Initialize Flask-Migrate

    # Register blueprints
    from .auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from .messaging import messaging_bp
    app.register_blueprint(messaging_bp, url_prefix='/api')

    from .admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    
    # JWT User Loader: Define how to get user identity from JWT
    # This is useful if you need to load the user object automatically
    # For this app, we'll primarily use get_jwt_identity() directly in routes
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"] # 'sub' is the default claim for identity
        user_id = identity.get('user_id')
        if user_id:
            return User.query.get(user_id)
        return None

    return app

# app/config.py
# This file defines different configuration settings for the Flask application
# (e.g., development, testing, production).
import os
from datetime import timedelta

# Base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration class. Contains common settings."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key_that_you_should_change'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'another_super_secret_jwt_key'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1) # Access tokens expire in 1 hour
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30) # Refresh tokens expire in 30 days
    # Add other common configurations here

class DevelopmentConfig(Config):
    """Development specific configurations."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'dev_app.db')
    # SQLALCHEMY_ECHO = True # Useful for debugging SQL queries

class TestingConfig(Config):
    """Testing specific configurations."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'test_app.db') # Use a separate DB for tests
    WTF_CSRF_ENABLED = False # Disable CSRF for testing forms if any
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=5) # Short expiry for testing

class ProductionConfig(Config):
    """Production specific configurations."""
    DEBUG = False
    # Ensure DATABASE_URL is set in the production environment
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'prod_app.db')
    # Add other production settings like logging, security headers, etc.

# Dictionary to access configuration classes by name
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# app/extensions.py
# This file initializes instances of Flask extensions.
# These instances are then configured and registered with the app in `create_app`.
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate # Added for database migrations

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
migrate = Migrate() # Instantiate Migrate

# app/models.py
# This file defines the SQLAlchemy database models for the application.
from datetime import datetime
from .extensions import db, bcrypt # bcrypt for password checking in User model

# Association table for many-to-many relationship between Messages and Tags (for public messages)
message_tags_association = db.Table('message_tags',
    db.Column('message_id', db.Integer, db.ForeignKey('message.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

# Association table for many-to-many relationship between Users and Tags (for subscriptions)
user_tag_subscriptions_association = db.Table('user_tag_subscriptions',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class User(db.Model):
    """User model for storing user accounts (admin and clients)."""
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_private_messages = db.relationship('MessageRecipient', backref='recipient_user', lazy='dynamic')
    # For tag subscriptions
    subscribed_tags = db.relationship('Tag', secondary=user_tag_subscriptions_association, lazy='subquery',
                                      backref=db.backref('subscribers', lazy=True))

    def __repr__(self):
        return f'<User {self.username} (Admin: {self.is_admin})>'

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Message(db.Model):
    """Message model for storing all types of messages."""
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Message types: 'private', 'group', 'public'
    message_type = db.Column(db.String(20), nullable=False) 
    
    # Relationships
    # For private/group messages, specific recipients are stored in MessageRecipient
    recipients_link = db.relationship('MessageRecipient', backref='message_info', lazy='dynamic', cascade="all, delete-orphan")
    # For public messages, tags are stored
    tags = db.relationship('Tag', secondary=message_tags_association, lazy='subquery',
                           backref=db.backref('messages_with_tag', lazy=True))

    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} type {self.message_type}>'

class MessageRecipient(db.Model):
    """
    Stores recipients for private and group messages.
    For a private message, there will be one entry.
    For a group message, there will be multiple entries (one for each recipient).
    """
    __tablename__ = 'message_recipient'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # is_read = db.Column(db.Boolean, default=False) # Optional: track read status

    def __repr__(self):
        return f'<MessageRecipient for Message {self.message_id} to User {self.recipient_id}>'

class Tag(db.Model):
    """Tag model for categorizing public messages."""
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f'<Tag {self.name}>'

# app/auth/__init__.py
# Initializes the authentication blueprint.
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)

from . import routes # Import routes after blueprint creation to avoid circular imports

# app/auth/routes.py
# Contains routes related to authentication, like login.
from flask import request, jsonify
from . import auth_bp
from app.models import User
from app.extensions import bcrypt, db # For password checking and db access
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Logs in a user (admin or client) and returns JWT access and refresh tokens.
    Expects JSON payload with 'username' and 'password'.
    """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Identity for JWT: can be any JSON serializable data
        # Storing user_id and is_admin status in the token
        identity_data = {'user_id': user.id, 'is_admin': user.is_admin, 'username': user.username}
        access_token = create_access_token(identity=identity_data)
        refresh_token = create_refresh_token(identity=identity_data) # Optional: for refreshing access tokens
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True) # Requires a valid refresh token
def refresh():
    """
    Provides a new access token using a refresh token.
    """
    current_user_identity = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_identity)
    return jsonify(access_token=new_access_token), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logs out a user by blacklisting the token (if using token blacklisting).
    Flask-JWT-Extended supports token blacklisting, but it requires additional setup (e.g., a blacklist store).
    For simplicity, this example doesn't implement full blacklisting.
    The client should discard the token upon logout.
    """
    # To implement true logout with JWT, you need a token blacklist.
    # jti = get_jwt()['jti']
    # Add jti to blacklist store (e.g., Redis, database)
    # For now, we just acknowledge the request. Client must delete the token.
    return jsonify({"msg": "Logout successful. Please discard your token."}), 200


# app/messaging/__init__.py
# Initializes the messaging blueprint.
from flask import Blueprint

messaging_bp = Blueprint('messaging', __name__)

from . import routes # Import routes

# app/messaging/routes.py
# Contains routes for sending, receiving, and managing messages.
from flask import request, jsonify
from . import messaging_bp
from app.models import User, Message, MessageRecipient, Tag, MessageTag, db
from app.extensions import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.orm import aliased
from sqlalchemy import or_

def get_current_user_id():
    """Helper function to get the current user's ID from JWT identity."""
    identity = get_jwt_identity()
    return identity.get('user_id') if identity else None

def is_admin_user():
    """Helper function to check if the current user is an admin from JWT identity."""
    identity = get_jwt_identity()
    return identity.get('is_admin', False) if identity else False

# --- Message Sending Endpoints ---
@messaging_bp.route('/messages/private', methods=['POST'])
@jwt_required()
def send_private_message():
    """
    Sends a private message from the authenticated user to a specified recipient.
    Expects JSON: {"recipient_username": "user2", "content": "Hello!"}
    """
    current_user_id = get_current_user_id()
    data = request.get_json()

    if not data or not data.get('recipient_username') or not data.get('content'):
        return jsonify({"msg": "Missing recipient_username or content"}), 400

    recipient_username = data['recipient_username']
    content = data['content']

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({"msg": f"Recipient user '{recipient_username}' not found"}), 404
    
    if recipient.id == current_user_id:
        return jsonify({"msg": "Cannot send a private message to yourself this way."}), 400

    try:
        message = Message(sender_id=current_user_id, content=content, message_type='private')
        db.session.add(message)
        db.session.flush() # To get message.id before committing

        message_recipient = MessageRecipient(message_id=message.id, recipient_id=recipient.id)
        db.session.add(message_recipient)
        
        db.session.commit()
        return jsonify({"msg": "Private message sent successfully", "message_id": message.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to send private message", "error": str(e)}), 500

@messaging_bp.route('/messages/group', methods=['POST'])
@jwt_required()
def send_group_message():
    """
    Sends a group message from the authenticated user to specified recipients.
    Expects JSON: {"recipient_usernames": ["user2", "user3"], "content": "Group update!"}
    """
    current_user_id = get_current_user_id()
    data = request.get_json()

    if not data or not data.get('recipient_usernames') or not data.get('content'):
        return jsonify({"msg": "Missing recipient_usernames or content"}), 400

    recipient_usernames = data['recipient_usernames']
    content = data['content']

    if not isinstance(recipient_usernames, list) or not recipient_usernames:
        return jsonify({"msg": "recipient_usernames must be a non-empty list"}), 400

    recipients = User.query.filter(User.username.in_(recipient_usernames)).all()
    if len(recipients) != len(recipient_usernames):
        found_usernames = {r.username for r in recipients}
        missing_usernames = [u for u in recipient_usernames if u not in found_usernames]
        return jsonify({"msg": f"Some recipient users not found: {missing_usernames}"}), 404
    
    # Prevent sending to self in a group message context if desired, or filter out self
    recipient_ids = {r.id for r in recipients if r.id != current_user_id}
    if not recipient_ids:
         return jsonify({"msg": "No valid recipients for group message (excluding self or none found)."}), 400


    try:
        message = Message(sender_id=current_user_id, content=content, message_type='group')
        db.session.add(message)
        db.session.flush()

        for recipient_id in recipient_ids:
            message_recipient = MessageRecipient(message_id=message.id, recipient_id=recipient_id)
            db.session.add(message_recipient)
        
        db.session.commit()
        return jsonify({"msg": "Group message sent successfully", "message_id": message.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to send group message", "error": str(e)}), 500

@messaging_bp.route('/messages/public', methods=['POST'])
@jwt_required()
def send_public_message():
    """
    Sends a public message from the authenticated user with specified tags.
    Expects JSON: {"tags": ["announcement", "release"], "content": "New version out!"}
    """
    current_user_id = get_current_user_id()
    data = request.get_json()

    if not data or not data.get('content'): # Tags are optional
        return jsonify({"msg": "Missing content"}), 400

    tag_names = data.get('tags', []) # Tags can be an empty list
    content = data['content']

    if not isinstance(tag_names, list):
        return jsonify({"msg": "tags must be a list of strings"}), 400

    try:
        message = Message(sender_id=current_user_id, content=content, message_type='public')
        db.session.add(message)
        db.session.flush()

        for tag_name in tag_names:
            tag = Tag.query.filter_by(name=tag_name.lower()).first()
            if not tag:
                tag = Tag(name=tag_name.lower())
                db.session.add(tag)
                db.session.flush() # Get tag.id if new
            message.tags.append(tag) # Use the association
        
        db.session.commit()
        return jsonify({"msg": "Public message sent successfully", "message_id": message.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to send public message", "error": str(e)}), 500

# --- Message Retrieval Endpoints ---
@messaging_bp.route('/messages/private', methods=['GET'])
@jwt_required()
def get_private_messages():
    """Retrieves private messages for the authenticated user (both sent and received)."""
    current_user_id = get_current_user_id()
    
    # Messages sent by the user
    sent_private = Message.query.filter_by(sender_id=current_user_id, message_type='private').order_by(Message.timestamp.desc()).all()
    
    # Messages received by the user
    received_private_query = db.session.query(Message).join(MessageRecipient).\
        filter(MessageRecipient.recipient_id == current_user_id, Message.message_type == 'private').\
        order_by(Message.timestamp.desc())
    received_private = received_private_query.all()

    # Combine and format (avoid duplicates if a message appears in both, though logically shouldn't for 'private')
    # For now, just list them; a more complex union might be needed if logic allows self-messaging via this route
    
    messages_data = []
    for msg in sent_private:
        # Find recipient for sent messages
        mr = MessageRecipient.query.filter_by(message_id=msg.id).first()
        recipient_username = User.query.get(mr.recipient_id).username if mr else "Unknown"
        messages_data.append({
            "id": msg.id, "sender_username": User.query.get(msg.sender_id).username,
            "recipient_username": recipient_username, # Only one recipient for private
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })

    for msg in received_private:
        # Sender is directly on msg.sender
        sender_username = User.query.get(msg.sender_id).username
        messages_data.append({
            "id": msg.id, "sender_username": sender_username,
            "recipient_username": User.query.get(current_user_id).username, # Current user is the recipient
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })
    
    # A more robust way would be to ensure no duplicates and sort all by timestamp
    # This simple merge might list messages where user is sender and recipient separately if that was allowed
    # For now, assuming private messages are not to oneself.
    
    # Sort all collected messages by timestamp descending
    messages_data.sort(key=lambda x: x['timestamp'], reverse=True)
    # Remove duplicates by ID, keeping the first occurrence (which will be the most detailed one if logic differs)
    # This is a simple way to deduplicate if any message ended up in both lists (e.g. sent to self)
    final_messages = []
    seen_ids = set()
    for msg_data in messages_data:
        if msg_data['id'] not in seen_ids:
            final_messages.append(msg_data)
            seen_ids.add(msg_data['id'])

    return jsonify(final_messages), 200


@messaging_bp.route('/messages/group', methods=['GET'])
@jwt_required()
def get_group_messages():
    """Retrieves group messages where the authenticated user is either the sender or a recipient."""
    current_user_id = get_current_user_id()
    
    # Messages sent by the user
    sent_group = Message.query.filter_by(sender_id=current_user_id, message_type='group').all()
    
    # Messages where the user is a recipient
    received_group_query = db.session.query(Message).join(MessageRecipient).\
        filter(MessageRecipient.recipient_id == current_user_id, Message.message_type == 'group')
    received_group = received_group_query.all()

    # Combine and avoid duplicates
    all_user_messages = list(set(sent_group + received_group)) # set removes duplicates
    all_user_messages.sort(key=lambda m: m.timestamp, reverse=True) # Sort by timestamp

    messages_data = []
    for msg in all_user_messages:
        sender_username = User.query.get(msg.sender_id).username
        recipient_usernames = [User.query.get(mr.recipient_id).username for mr in msg.recipients_link.all()]
        messages_data.append({
            "id": msg.id, "sender_username": sender_username,
            "recipients_usernames": recipient_usernames,
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })
    return jsonify(messages_data), 200

@messaging_bp.route('/messages/public', methods=['GET'])
@jwt_required()
def get_public_messages():
    """
    Retrieves public messages based on the authenticated user's subscribed tags.
    If no tags subscribed, or no 'tags' query param, returns all public messages.
    Optionally filter by query param `tags=tag1,tag2`.
    """
    current_user_id = get_current_user_id()
    user = User.query.get(current_user_id)
    
    query_tags_str = request.args.get('tags')
    
    query = Message.query.filter_by(message_type='public')

    if query_tags_str: # Filter by specific tags in query param
        query_tag_names = [t.strip().lower() for t in query_tags_str.split(',')]
        query = query.join(Message.tags).filter(Tag.name.in_(query_tag_names))
    elif user.subscribed_tags: # Filter by user's subscribed tags if no specific query tags
        subscribed_tag_ids = [tag.id for tag in user.subscribed_tags]
        query = query.join(Message.tags).filter(Tag.id.in_(subscribed_tag_ids))
    # If no query_tags_str and no subscribed_tags, it fetches all public messages.

    messages = query.order_by(Message.timestamp.desc()).all()
    
    messages_data = []
    for msg in messages:
        sender_username = User.query.get(msg.sender_id).username
        message_tags = [tag.name for tag in msg.tags]
        messages_data.append({
            "id": msg.id, "sender_username": sender_username, "tags": message_tags,
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })
    return jsonify(messages_data), 200

# --- Tag Subscription Endpoints ---
@messaging_bp.route('/tags/subscribe', methods=['POST'])
@jwt_required()
def subscribe_to_tags():
    """
    Subscribes the authenticated user to specified tags.
    Expects JSON: {"tags": ["news", "updates"]}
    """
    current_user_id = get_current_user_id()
    user = User.query.get(current_user_id)
    data = request.get_json()

    if not data or not isinstance(data.get('tags'), list):
        return jsonify({"msg": "Missing 'tags' list in request"}), 400

    tag_names_to_subscribe = data['tags']
    
    try:
        for tag_name in tag_names_to_subscribe:
            tag = Tag.query.filter_by(name=tag_name.lower()).first()
            if not tag: # Create tag if it doesn't exist
                tag = Tag(name=tag_name.lower())
                db.session.add(tag)
                # db.session.flush() # Not strictly necessary here, commit will handle
            if tag not in user.subscribed_tags:
                user.subscribed_tags.append(tag)
        db.session.commit()
        current_subscriptions = [t.name for t in user.subscribed_tags]
        return jsonify({"msg": "Successfully subscribed to tags", "current_subscriptions": current_subscriptions}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to subscribe to tags", "error": str(e)}), 500

@messaging_bp.route('/tags/unsubscribe', methods=['POST'])
@jwt_required()
def unsubscribe_from_tags():
    """
    Unsubscribes the authenticated user from specified tags.
    Expects JSON: {"tags": ["news"]}
    """
    current_user_id = get_current_user_id()
    user = User.query.get(current_user_id)
    data = request.get_json()

    if not data or not isinstance(data.get('tags'), list):
        return jsonify({"msg": "Missing 'tags' list in request"}), 400

    tag_names_to_unsubscribe = data['tags']
    
    try:
        for tag_name in tag_names_to_unsubscribe:
            tag = Tag.query.filter_by(name=tag_name.lower()).first()
            if tag and tag in user.subscribed_tags:
                user.subscribed_tags.remove(tag)
        db.session.commit()
        current_subscriptions = [t.name for t in user.subscribed_tags]
        return jsonify({"msg": "Successfully unsubscribed from tags", "current_subscriptions": current_subscriptions}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to unsubscribe from tags", "error": str(e)}), 500

# --- Message Deletion Endpoint ---
@messaging_bp.route('/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    """
    Deletes a message based on its type and user permissions.
    - Private: deletable by sender, receiver, or admin.
    - Group: deletable by sender or admin.
    - Public: deletable by sender or admin.
    """
    current_user_id = get_current_user_id()
    is_current_user_admin = is_admin_user()
    
    message = Message.query.get(message_id)
    if not message:
        return jsonify({"msg": "Message not found"}), 404

    can_delete = False
    if is_current_user_admin:
        can_delete = True
    elif message.sender_id == current_user_id: # Sender can always delete their messages (as per rules)
        can_delete = True
    elif message.message_type == 'private':
        # Check if current user is the recipient
        recipient_link = MessageRecipient.query.filter_by(message_id=message.id, recipient_id=current_user_id).first()
        if recipient_link:
            can_delete = True
    
    # Group and Public messages are covered by sender or admin check already.

    if not can_delete:
        return jsonify({"msg": "You do not have permission to delete this message"}), 403

    try:
        # Related MessageRecipient and MessageTag entries will be deleted due to cascade if set up,
        # or handle manually if not. Here, MessageRecipient has cascade="all, delete-orphan".
        # For message_tags association, SQLAlchemy handles removal from association table.
        db.session.delete(message)
        db.session.commit()
        return jsonify({"msg": f"Message {message_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to delete message", "error": str(e)}), 500


# app/admin/__init__.py
# Initializes the admin blueprint.
from flask import Blueprint

admin_bp = Blueprint('admin', __name__)

from . import routes # Import routes

# app/admin/routes.py
# Contains routes for admin-specific functionalities.
from flask import jsonify
from . import admin_bp
from flask_jwt_extended import jwt_required
from app.messaging.routes import is_admin_user # Re-use the checker or make a common one

@admin_bp.route('/status', methods=['GET'])
@jwt_required()
def server_status():
    """
    Admin-only endpoint to check server status.
    """
    if not is_admin_user(): # Check if the user identified by JWT is an admin
        return jsonify({"msg": "Admin access required"}), 403
    
    # Basic status, can be expanded (e.g., DB connection, number of users/messages)
    status_info = {
        "status": "ok",
        "message": "Server is running.",
        "version": "1.0.0" 
    }
    return jsonify(status_info), 200

# app/utils/decorators.py
# (Optional) Can be used for custom decorators, e.g., more specific JWT role checks.
# For now, is_admin_user() check is done directly in routes.
# Example of a custom admin required decorator:
"""
from functools import wraps
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        identity = get_jwt_identity()
        if not identity or not identity.get('is_admin'):
            return jsonify(msg="Admins only!"), 403
        return fn(*args, **kwargs)
    return wrapper
"""
# If you use this, replace @jwt_required() and the manual check with @admin_required for admin routes.

