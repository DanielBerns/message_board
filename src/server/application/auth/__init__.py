# app/auth/__init__.py
# Initializes the authentication blueprint.
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)

from . import routes # Import routes after blueprint creation to avoid circular imports

