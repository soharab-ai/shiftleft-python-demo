import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    
    if username is None or password is None or access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Added input validation for username using whitelist approach
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return jsonify({"error": "Username must be 3-30 characters and contain only letters, numbers, and underscores"}), 400
        
    # Enhanced password strength validation
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    if not (re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and re.search(r'[0-9]', password)):
        return jsonify({"error": "Password must contain at least one uppercase letter, one lowercase letter, and one number"}), 400

    # Validate access_level parameter
    try:
        access_level_int = int(access_level)
        if access_level_int < 0 or access_level_int > 2:  # Assuming valid access levels are 0, 1, 2
            return jsonify({"error": "Invalid access level value"}), 400
    except ValueError:
        return jsonify({"error": "access_level must be a valid integer"}), 400
    
    # Hash password instead of storing plaintext
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    # Use stored procedure for user creation if available, otherwise use parameterized query
    try:
        # Try to use stored procedure if it exists
        query = "CALL create_user(?, ?, ?)"
        params = (username, hashed_password, access_level_int)
        query_db(query, params, False, True)
        return jsonify({"success": True})
    except sqlite3.Error as first_err:
        try:
            # Fallback to parameterized query if stored procedure doesn't exist
            query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
            params = (username, hashed_password, access_level_int)
            query_db(query, params, False, True)
            return jsonify({"success": True})
        except sqlite3.Error as err:
            return jsonify({"error": f"Could not create user: {str(err)}"})
