import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


def validate_username(username):
    # SECURE: Schema-aware length validation to prevent truncation attacks
    schema = get_schema_constraints()
    USERNAME_MAX_LENGTH = schema['username']['max_length']
    
    if len(username) > USERNAME_MAX_LENGTH:
        raise ValueError(f"Username exceeds maximum length of {USERNAME_MAX_LENGTH} characters")
    
    # SECURE: Input validation - only allow alphanumeric characters and underscores, 3-20 characters
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Username must be 3-20 alphanumeric characters and underscores only")
    return username

        return (
def validate_access_level(access_level):
    # SECURE: Input validation - only allow valid access levels (0, 1, 2)
    level = int(access_level)
    if level not in [0, 1, 2]:
        raise ValueError("Invalid access level. Must be 0, 1, or 2")
    return level

    if len(password) < 3:
def validate_password(password):
    # SECURE: Enhanced password validation with schema-aware length check
    schema = get_schema_constraints()
    PASSWORD_MAX_LENGTH = schema['password']['max_length']
    
    if len(password) < 3:
        raise ValueError("Password must be at least 3 characters long")
    
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password exceeds maximum length of {PASSWORD_MAX_LENGTH} characters")
    
    return password

        query_db(query, [], False, True)
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_param = request.form.get("access_level")
    
    if username is None or password is None or access_level_param is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )

    try:
        # SECURE: Validate password with schema-aware length constraints
        validated_password = validate_password(password)
        
        # SECURE: Validate username format with schema-aware constraints
        validated_username = validate_username(username)
        
        # SECURE: Validate access_level is an integer and within allowed range
        validated_access_level = validate_access_level(access_level_param)
        
        # SECURE: Hash password instead of storing plaintext
        hashed_password = generate_password_hash(validated_password, method='pbkdf2:sha256')
        
        # SECURE: Use parameterized query with placeholders to prevent SQL injection
        # SECURE: Explicit prepared statement approach with validated parameters
        query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
        
        # SECURE: Pass parameters as tuple - they will be properly escaped by prepared statement
        query_db(query, (validated_username, hashed_password, validated_access_level), False, True)
        return jsonify({"success": True})
    except ValueError as ve:
        # SECURE: Return validation error without exposing internal details
        return jsonify({"error": str(ve)}), 400
    except sqlite3.Error as err:
        # SECURE: Log error server-side but return generic error to user to avoid information disclosure
        # Note: In production, use proper logging framework instead of print
        print(f"Database error during user creation: {err}")
        return jsonify({"error": "could not create user"}), 500
