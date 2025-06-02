# app/messaging/__init__.py
# Initializes the messaging blueprint.
from flask import Blueprint

messaging_bp = Blueprint('messaging', __name__)

from . import routes # Import routes

