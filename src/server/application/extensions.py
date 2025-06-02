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

