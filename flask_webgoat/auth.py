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
    
    # Input validation for username and password format
    if not is_valid_username(username) or not is_valid_password_format(password):
        return jsonify({"error": "Invalid credentials format"}), 400
    
    # Rate limiting check to prevent brute force attacks
    if is_rate_limited(request.remote_addr):
        return jsonify({"error": "Too many failed attempts"}), 429
    
    try:
        # Fixed SQL Injection by using parameterized query and proper password handling
        # First retrieve user without checking password in SQL
        query = "SELECT id, username, access_level, password_hash FROM user WHERE username = ?"
        result = query_db(query, (username,), True)
        
        # Verify password outside of SQL query
        if result and verify_password(password, result[3]):
            session["user_info"] = (result[0], result[1], result[2])
            # Reset failed attempts on successful login
            reset_failed_attempts(request.remote_addr)
            return jsonify({"success": True})
        else:
            # Log failed attempt
            record_failed_attempt(request.remote_addr)
            return jsonify({"bad_login": True}), 400
    except sqlite3.Error as e:
        # Added error handling for database errors
        logging.error(f"Database error during login attempt: {str(e)}")
        return jsonify({"error": "System error occurred"}), 500

def is_valid_username(username):
    # Allow alphanumeric and some special characters, limit length
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]{3,30}$', username))

def is_valid_password_format(password):
    # Basic check for minimum complexity
    return len(password) >= 8

def verify_password(plain_text_password, stored_hash):
    # Compare password using secure verification
    try:
        return bcrypt.checkpw(plain_text_password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception:
        return False

# Rate limiting implementation
failed_attempts = null
def is_rate_limited(ip_address):
    current_time = time.time()
    if ip_address in failed_attempts:
        attempts = [t for t in failed_attempts[ip_address] if current_time - t < 3600]  # 1 hour window
        failed_attempts[ip_address] = attempts
        return len(attempts) >= 5  # Limit to 5 attempts per hour
    return False

def record_failed_attempt(ip_address):
    current_time = time.time()
    if ip_address not in failed_attempts:
        failed_attempts[ip_address] = []
    failed_attempts[ip_address].append(current_time)

def reset_failed_attempts(ip_address):
    if ip_address in failed_attempts:
        failed_attempts[ip_address] = []

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
