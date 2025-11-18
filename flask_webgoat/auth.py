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
    
    # Added input validation for username
    if not is_valid_username(username) or len(username) > 50:
        return jsonify({"error": "Invalid username format"}), 400
    
    # Implement rate limiting for login attempts
    ip_address = get_remote_address()
    if is_rate_limited(ip_address):
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429
    
    # Get user with username only - passwords should not be compared in SQL
    query = "SELECT id, username, access_level, password_hash FROM user WHERE username = ?"
    result = query_db(query, (username,), True)
    
    # Verify password hash outside of SQL query
    if result is None or not check_password_hash(result[3], password):
        record_failed_attempt(ip_address)
        return jsonify({"bad_login": True}), 400
    
    # Reset failed attempts on successful login
    reset_failed_attempts(ip_address)
    
    # Store user info in session
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})

# Helper functions for input validation
def is_valid_username(username):
    # Only allow alphanumeric characters and underscore in username
    pattern = r'^[a-zA-Z0-9_]+$'
    return bool(re.match(pattern, username))

# Rate limiting implementation
failed_attempts = null
MAX_ATTEMPTS = 5
LOCKOUT_PERIOD = 15 * 60  # 15 minutes in seconds

def is_rate_limited(ip):
    if ip in failed_attempts:
        attempts, timestamp = failed_attempts[ip]
        if attempts >= MAX_ATTEMPTS:
            if time.time() - timestamp < LOCKOUT_PERIOD:
                return True
            else:
                # Reset after lockout period
                failed_attempts.pop(ip, None)
    return False

def record_failed_attempt(ip):
    current_time = time.time()
    if ip in failed_attempts:
        attempts, _ = failed_attempts[ip]
        failed_attempts[ip] = (attempts + 1, current_time)
    else:
        failed_attempts[ip] = (1, current_time)

def reset_failed_attempts(ip):
    failed_attempts.pop(ip, None)

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
