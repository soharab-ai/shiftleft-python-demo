import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    # Validate CSRF token for form submission
    try:
        validate_csrf(request.form.get('csrf_token'))
    except:
        return jsonify({"error": "CSRF validation failed"}), 400

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
        
    # Enhanced input validation with length limits
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    # Added username length validation
    if len(username) > 50:
        return jsonify({"error": "username too long (maximum 50 characters)"}), 400
    
    # Added stronger username validation
    if not username.isalnum():
        return jsonify({"error": "username can only contain alphanumeric characters"}), 400
    
    # Validate access_level is a valid integer value
    try:
        access_level_int = int(access_level)
        # Check access_level is in allowed range
        if access_level_int not in [0, 1, 2]:  # Example of allowed levels
            return jsonify({"error": "invalid access level (must be 0, 1, or 2)"}), 400
    except ValueError:
        return jsonify({"error": "access_level must be an integer"}), 400
    
    # Password hashing implementation
    hashed_password = generate_password_hash(password)
    
    # Fixed SQL injection by using parameterized query
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    params = (username, hashed_password, access_level_int)

    try:
        query_db(query, params, False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        # Improved error handling without exposing internal details
        logger = logging.getLogger(__name__)
        logger.error("Database error during user creation: %s", str(err))
        return jsonify({"error": "An error occurred while creating the user"}), 500

