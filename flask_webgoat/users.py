import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)

def validate_username(username):
    """Validate username format to prevent SQL injection and ensure data integrity"""
    # Allow only alphanumeric characters and underscores, 3-20 characters
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format: must be 3-20 alphanumeric characters or underscores")
    return username

    access_level = user_info[2]
def validate_access_level(access_level):
    """Validate access level to ensure it's a valid integer within allowed range"""
    # Ensure access_level is a valid integer within allowed range
    try:
        level = int(access_level)
        if level not in [0, 1, 2, 3]:  # Define allowed access levels
            raise ValueError("Invalid access level: must be 0, 1, 2, or 3")
        return level
    except (ValueError, TypeError):
        raise ValueError("Access level must be a valid integer")

def hash_password(password):
    """Hash password using PBKDF2-HMAC-SHA256 with salt for secure storage"""
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"}), 401

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"}), 403
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    
    if username is None or password is None or access_level is None:
        return jsonify({
            "error": "username, password and access_level parameters have to be provided"
        }), 400
    
    if len(password) < 3:
        return jsonify({"error": "the password needs to be at least 3 characters long"}), 400
    
    try:
        # FIX: Validate username input to prevent SQL injection
        username = validate_username(username)
        
        # FIX: Validate access_level input to ensure valid integer
        validated_access_level = validate_access_level(access_level)
        
        # FIX: Hash password instead of storing plaintext
        hashed_password = hash_password(password)
        
        # FIX: Use parameterized query instead of string concatenation to prevent SQL injection
        query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
        query_db(query, [username, hashed_password, validated_access_level], False, True)
        
        return jsonify({"success": True}), 201
    except ValueError as ve:
        # FIX: Handle validation errors with appropriate error messages
        return jsonify({"error": str(ve)}), 400
    except sqlite3.IntegrityError:
        # FIX: Handle duplicate username constraint violation
        return jsonify({"error": "username already exists"}), 409
    except sqlite3.Error as err:
        # FIX: Prevent information disclosure by not exposing internal error details
        return jsonify({"error": "could not create user"}), 500
