from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import logging
from utils.db import users_col, verify_password

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/api/auth/login", methods=["POST"])
def api_login():
    """User login endpoint"""
    try:
        data = request.get_json()
        if not data.get('email') or not data.get('password'):
            return jsonify({"success": False, "error": "Email and password required"}), 400

        user = users_col.find_one({"email": data['email'].lower()})
        if not user or not verify_password(data['password'], user['password']):
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        access_token = create_access_token(identity=str(user['_id']))
        logger.info(f"✅ User logged in: {user['username']}")
        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": access_token,
            "user": {
                "id": str(user['_id']),
                "username": user['username'],
                "email": user['email'],
                "role": user.get('role', 'staff')
            }
        }), 200
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "error": "Login failed"}), 500

@auth_bp.route("/api/auth/verify", methods=["GET"])
@jwt_required()
def verify_token():
    """Verify if token is valid"""
    try:
        user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        return jsonify({
            "success": True,
            "user": {
                "id": str(user['_id']),
                "username": user['username'],
                "email": user['email'],
                "role": user.get('role', 'staff')
            }
        }), 200
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({"success": False, "error": "Invalid token"}), 401
