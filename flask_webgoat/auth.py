from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
# Initialize CSRF protection
csrf = CSRFProtect()

# Configure secure session settings
def configure_session_security(app):
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )

@limiter.limit("5/minute")
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "Invalid credentials"}),  # Generic error message for security
            400,
        )

    # Input validation to prevent malicious input
    if not re.match(r'^[a-zA-Z0-9_]+$', username) or not re.match(r'^[a-zA-Z0-9_!@#$%^&*]+$', password):
        return jsonify({"error": "Invalid credentials"}), 400  # Generic error for security
        
    # Fixed password storage vulnerability by comparing hashed passwords
    query = "SELECT id, username, password_hash, access_level FROM user WHERE username = ?"
    result = query_db(query, (username,), True)
    
    # Check if user exists and password is correct using secure hash comparison
    if result is None or not check_password_hash(result[2], password):
        return jsonify({"error": "Invalid credentials"}), 400  # Generic error for security
    
    # Store necessary user info in session
    session["user_info"] = (result[0], result[1], result[3])  # id, username, access_level
    return jsonify({"success": True})

def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        # vulnerability: Open Redirect
        return redirect(url)
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})
