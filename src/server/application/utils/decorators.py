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

