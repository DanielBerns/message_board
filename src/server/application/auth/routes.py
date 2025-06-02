# app/auth/routes.py
# Contains routes related to authentication, like login.
from flask import request, jsonify
from . import auth_bp
from application.models import User
from application.extensions import bcrypt, db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Logs in a user (admin or client) and returns JWT access and refresh tokens.
    Identity in JWT will be the user's ID as a string.
    """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Store user's ID as a string in the JWT identity
        string_identity = str(user.id)
        access_token = create_access_token(identity=string_identity)
        refresh_token = create_refresh_token(identity=string_identity)
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True) # Requires a valid refresh token
def refresh():
    """
    Provides a new access token using a refresh token.
    The identity from the refresh token (user ID string) is used for the new access token.
    """
    current_user_identity_str = get_jwt_identity() # This will be the user ID string
    new_access_token = create_access_token(identity=current_user_identity_str)
    return jsonify(access_token=new_access_token), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logs out a user. Currently, this is a conceptual logout.
    The client should discard the token. True server-side blacklisting is not implemented.
    """
    # To implement true logout with JWT, you need a token blacklist.
    # Example:
    # jti = get_jwt()['jti']
    # add_to_blacklist(jti) # Your function to store jti in a blacklist (e.g., Redis, DB)
    return jsonify({"msg": "Logout successful. Please discard your token."}), 200


