# app/admin/__init__.py
# Initializes the admin blueprint.
from flask import Blueprint

admin_bp = Blueprint('admin', __name__)

from . import routes # Import routes

