import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
def create_user():
    # Enhanced session validation
    user_info = session.get("user_info", None)
    if user_info is None or not isinstance(user_info, (list, tuple)) or len(user_info) < 3:
        return jsonify({"error": "Invalid or missing user_info in session"}), 401

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"}), 403
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_input = request.form.get("access_level")
    
    if username is None or password is None or access_level_input is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Enhanced input validation
    # Username validation - alphanumeric with underscores, 4-20 chars
    if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
        return jsonify({"error": "Username must be 4-20 characters and contain only letters, numbers, and underscores"}), 400
    
    # Password complexity validation
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    if not (re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and 
            re.search(r'[0-9]', password) and re.search(r'[^a-zA-Z0-9]', password)):
        return jsonify({"error": "Password must include uppercase, lowercase, number and special character"}), 400
    
    # Access level validation
    allowed_access_levels = ["0", "1", "2"]
    if access_level_input not in allowed_access_levels:
        return jsonify({"error": "Invalid access level provided"}), 400
    
    # Password hashing implementation
    hashed_password = generate_password_hash(password)
    
    # SQL Injection prevention with parameterized query
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    params = [username, hashed_password, int(access_level_input)]

    try:
        query_db(query, params, False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        # Secure error handling - log actual error but return generic message
        logging.error(f"Database error when creating user: {str(err)}")
        return jsonify({"error": "An error occurred while creating the user. Please try again later."}), 500
