# app/__init__.py
# This file contains the application factory function `create_app`.
# It initializes the Flask app, configures it, initializes extensions, and registers blueprints.
import os
from flask import Flask
from .config import config
from .extensions import db, bcrypt, jwt, migrate
from .models import User # Ensure models are imported

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

    # JWT User Loader: Define how to get user object from JWT identity
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """
        This function is called whenever current_user is accessed in a protected route.
        jwt_data["sub"] will be the identity provided when the token was created (now a string user ID).
        """
        identity_str = jwt_data["sub"] # Identity is now the user ID as a string
        try:
            user_id = int(identity_str)
            return User.query.get(user_id)
        except (ValueError, TypeError):
            # Log error or handle case where identity_str is not a valid int string
            return None
        return None

    return app

