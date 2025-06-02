# app/admin/routes.py
# Contains routes for admin-specific functionalities.
from flask import jsonify
from . import admin_bp
from flask_jwt_extended import jwt_required # current_user will be used via helper
# Import the updated helper function from messaging.routes or a common utils module
from application.messaging.routes import is_admin_user_from_current_user_obj
from application.models import User # Required for isinstance check in the helper if not already imported by it

@admin_bp.route('/status', methods=['GET'])
@jwt_required()
def server_status():
    """
    Admin-only endpoint to check server status.
    """
    if not is_admin_user_from_current_user_obj(): # Use the helper that checks current_user.is_admin
        return jsonify({"msg": "Admin access required"}), 403

    status_info = {
        "status": "ok",
        "message": "Server is running.",
        "version": "1.0.0"
    }
    return jsonify(status_info), 200

