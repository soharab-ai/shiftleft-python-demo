import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_str = request.form.get("access_level")
    
    # Added input validation for required fields
    if username is None or password is None or access_level_str is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Added input length restriction to prevent DoS attacks
    if len(username) > 50:
        return jsonify({"error": "Username exceeds maximum allowed length (50 characters)"}), 400
    
    # Added input validation for username using regex (alphanumeric + some special chars)
    if not re.match(r'^[a-zA-Z0-9_-.@]+$', username):
        return jsonify({"error": "Username contains invalid characters"}), 400
    
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    try:
        # Convert and validate access_level
        try:
            access_level_int = int(access_level_str)
            if access_level_int not in [0, 1, 2]:  # Assuming only these values are valid
                return jsonify({"error": "Invalid access level value"}), 400
        except ValueError:
            return jsonify({"error": "Access level must be a number"}), 400
            
        # Hash the password with bcrypt before storage
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Using SQLAlchemy ORM instead of raw SQL queries
        new_user = User(
            username=username, 
            password=hashed_password.decode('utf-8'),  # Store hash as string
            access_level=access_level_int
        )
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({"success": True})
    except Exception:
        # Improved error handling to prevent exposing database details
        db.session.rollback()
        return jsonify({"error": "Database error occurred while creating user"}), 500

