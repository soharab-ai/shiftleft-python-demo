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
    
    # Extract request parameters
    username = request.form.get("username")
    password = request.form.get("password")
    new_access_level = request.form.get("access_level")
    
    # Validate required parameters
    if username is None or password is None or new_access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Enhanced input validation
    username_validation = validate_username(username)
    if username_validation:
        return jsonify({"error": username_validation}), 400
    
    password_validation = validate_password(password)
    if password_validation:
        return jsonify({"error": password_validation}), 400
    
    try:
        # Convert and validate access_level
        parsed_access_level = int(new_access_level)
        access_level_validation = validate_access_level(parsed_access_level)
        if access_level_validation:
            return jsonify({"error": access_level_validation}), 400
            
        # Use service layer for user creation (includes password hashing and DB transactions)
        user_service = UserService()
        result = user_service.create_user(username, password, parsed_access_level)
        
        if result["success"]:
            return jsonify({"success": True})
        else:
            # Standardized error message that doesn't expose implementation details
            return jsonify({"error": "Failed to create user"}), 500
            
    except ValueError:
        return jsonify({"error": "access_level must be a number"}), 400
    except Exception as e:
        # Log the actual error for debugging but don't expose it to users
        logging.error(f"Error creating user: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

