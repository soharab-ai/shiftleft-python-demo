from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
# Configure rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Dictionary to track login attempts
login_attempts = null
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes in seconds

def exceeded_login_attempts(username):
    current_time = time.time()
    if username in login_attempts:
        attempts, lockout_time = login_attempts[username]
        if lockout_time > current_time:
            return True
        if attempts >= MAX_ATTEMPTS:
            # Set lockout time
            login_attempts[username] = (attempts, current_time + LOCKOUT_TIME)
            return True
    return False

def increment_login_attempts(username):
    current_time = time.time()
    if username in login_attempts:
        attempts, lockout_time = login_attempts[username]
        if lockout_time <= current_time:  # Reset if lockout expired
            login_attempts[username] = (1, 0)
        else:
            login_attempts[username] = (attempts + 1, lockout_time)
    else:
        login_attempts[username] = (1, 0)

@limiter.limit("10 per minute")  # Added rate limiting decorator
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )
    
    # Improved input validation with positive pattern matching instead of blacklisting
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return jsonify({"error": "Username contains invalid characters"}), 400
    
    # Check for rate limiting/brute force protection
    if exceeded_login_attempts(username):
        return jsonify({"error": "Too many login attempts, account temporarily locked"}), 429
    
    # Using SQLAlchemy for database operations instead of direct SQL
    try:
        # Get user by username only, password will be checked separately
        query = text("SELECT id, username, password_hash, access_level FROM user WHERE username = :username")
        result = query_db(query, {"username": username}, True)
        
        if result is None or not check_password_hash(result[2], password):
            # Increment failed login attempts
            increment_login_attempts(username)
            return jsonify({"bad_login": True}), 400
            
        # Reset login attempts on successful login
        if username in login_attempts:
            login_attempts[username] = (0, 0)
            
        # Store user info in session
        session["user_info"] = (result[0], result[1], result[3])  # id, username, access_level
        return jsonify({"success": True})
    except Exception as e:
        # Log the error securely without exposing sensitive info
        print(f"Login error occurred at {datetime.now()}: Internal server error")
        return jsonify({"error": "An internal error occurred"}), 500

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
