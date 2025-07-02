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
    
    # Added input validation for username using regex pattern
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return jsonify({"error": "Username must be 3-30 characters and contain only letters, numbers, and underscores"}), 400
    
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    try:
        # Added range check for access_level
        access_level_int = int(access_level)
        if access_level_int < 0 or access_level_int > 2:
            return jsonify({"error": "access_level must be between 0 and 2"}), 400
            
        # Added username uniqueness check
        check_query = "SELECT COUNT(*) FROM user WHERE username = ?"
        result = query_db(check_query, (username,), True)
        if result[0] > 0:
            return jsonify({"error": "Username already exists"}), 409
        
        # Implemented password hashing for security
        hashed_password = generate_password_hash(password)
        
        # SQL Injection protection using parameterized queries
        query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
        params = (username, hashed_password, access_level_int)

        # Added transaction management
        try:
            # Begin transaction
            query_db("BEGIN", (), False, False)
            query_db(query, params, False, True)
            query_db("COMMIT", (), False, False)
            return jsonify({"success": True})
        except sqlite3.Error as err:
            query_db("ROLLBACK", (), False, False)
            # Log the actual error details server-side but don't expose to user
            logging.error(f"Database error while creating user: {str(err)}")
            return jsonify({"error": "An error occurred while creating user"}), 500
            
    except ValueError:
        return jsonify({"error": "access_level must be a valid integer"}), 400
    except Exception as e:
        # Generic error handling to avoid exposing implementation details
        logging.error(f"Unexpected error in create_user: {str(e)}")
        return jsonify({"error": "An error occurred while processing your request"}), 500
