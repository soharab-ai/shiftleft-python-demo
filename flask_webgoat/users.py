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
    
    # CSRF protection check
    try:
        validate_csrf(request.form.get('csrf_token'))
    except:
        return jsonify({"error": "CSRF token validation failed"}), 403
    
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
    
    # Input sanitization for username
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username contains invalid characters"}), 400
        
    # Username uniqueness check
    existing_user = query_db("SELECT username FROM user WHERE username = ?", [username], True)
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409
    
    # Password strength validation
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    # Additional password strength requirements
    if not validate_password_strength(password):
        return jsonify({"error": "Password doesn't meet security requirements"}), 400
    
    # Hash password before storing
    hashed_password = generate_password_hash(password)
    
    # Input validation for access_level
    try:
        access_level_int = int(access_level)
    except ValueError:
        return jsonify({"error": "access_level must be an integer"}), 400
    
    # Access Level Range Check
    MAX_ACCESS_LEVEL = 2  # Define appropriate maximum access level
    if not (0 <= access_level_int <= MAX_ACCESS_LEVEL):
        return jsonify({"error": f"Access level must be between 0 and {MAX_ACCESS_LEVEL}"}), 400
    
    try:
        # Using direct connection with parameterized query for more consistent security
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)",
            (username, hashed_password, access_level_int)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except sqlite3.Error as err:
        return jsonify({"error": "could not create user: " + str(err)})

def validate_password_strength(password):
    """
    Validates password strength requirements:
    - At least 8 characters
    - Contains uppercase letter
    - Contains lowercase letter
    - Contains a digit
    - Contains a special character
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )

    # vulnerability: SQL Injection
    query = (
        "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
        % (username, password, int(access_level))
    )

    try:
        query_db(query, [], False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        return jsonify({"error": "could not create user:" + err})
