# app/config.py
# This file defines different configuration settings for the Flask application
# (e.g., development, testing, production).
import os
from datetime import timedelta

from .storage import info_root, get_resource

# Base directory of the application
IDENTIFIER = "messages_board"
VERSION = "alpha"
INFO_ROOT = info_root(IDENTIFIER, VERSION)

class Config:
    """Base configuration class. Contains common settings."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key_that_you_should_change'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'another_super_secret_jwt_key'
    LOGGING_LEVEL = os.environ.get('LOGGING_LEVEL') or "DEBUG"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1) # Access tokens expire in 1 hour
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30) # Refresh tokens expire in 30 days

class DevelopmentConfig(Config):
    """Development specific configurations."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + str(get_resource(INFO_ROOT, "dev_messages_board", ".db")) # Use a separate DB for development
    # SQLALCHEMY_ECHO = True # Useful for debugging SQL queries

class TestingConfig(Config):
    """Testing specific configurations."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + str(get_resource(INFO_ROOT, "test_messages_board", ".db")) # Use a separate DB for tests
    WTF_CSRF_ENABLED = False # Disable CSRF for testing forms if any
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=5) # Short expiry for testing

class ProductionConfig(Config):
    """Production specific configurations."""
    DEBUG = False
    # Ensure DATABASE_URL is set in the production environment
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + str(get_resource(INFO_ROOT, "prod_messages_board", ".db")) # Use a separate DB for production
    # Add other production settings like logging, security headers, etc.

# Dictionary to access configuration classes by name
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

