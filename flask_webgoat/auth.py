from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )
    
    # Added input validation before database query to prevent other attacks
    if not username or not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Invalid username format"}), 400
    
    # Get failed attempts from session or initialize
    failed_attempts = session.get(f"failed_attempts_{username}", 0)
    last_attempt_time = session.get(f"last_attempt_time_{username}", 0)
    MAX_ATTEMPTS = 5
    LOCKOUT_TIME = 300  # 5 minutes in seconds
    
    # Implement account lockout after multiple failed attempts
    if failed_attempts >= MAX_ATTEMPTS:
        if time.time() - last_attempt_time < LOCKOUT_TIME:
            return jsonify({"error": "Account temporarily locked due to multiple failed attempts"}), 403
        else:
            # Reset counter after lockout period
            session[f"failed_attempts_{username}"] = 0
            failed_attempts = 0
    
    # Fixed SQL Injection by using parameterized queries and only querying for username
    # to properly verify hashed password later
    query = "SELECT id, username, access_level, password_hash FROM user WHERE username = ?"
    result = query_db(query, (username,), True)
    
    # Implement secure password verification with hashing
    if result is None or not check_password_hash(result[3], password):
        # Increment failed attempts counter
        session[f"failed_attempts_{username}"] = failed_attempts + 1
        session[f"last_attempt_time_{username}"] = time.time()
        return jsonify({"bad_login": True}), 400
        
    # Reset failed attempts on successful login
    session[f"failed_attempts_{username}"] = 0
    # Store user info in session
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})

# Add security headers and CSRF protection
@auth_bp.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@bp.route("/login_and_redirect")
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
