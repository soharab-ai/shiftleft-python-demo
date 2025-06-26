from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Track failed login attempts
failed_attempts = null

@limiter.limit("10 per minute") # Added rate limiting to prevent brute force attacks
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    # Enhanced input validation
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameters have to be provided"}),
            400,
        )
    
    # Added strict input validation for username
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return jsonify({"error": "Invalid username format"}), 400
    
    # Check if user has too many failed attempts
    client_ip = get_remote_address()
    if client_ip in failed_attempts:
        if len(failed_attempts[client_ip]) >= 5 and time.time() - failed_attempts[client_ip][-5] < 300:
            return jsonify({"error": "Too many failed attempts. Try again later"}), 429

    # Query only by username - improved security by not including password in the query
    query = "SELECT id, username, access_level, password_hash FROM user WHERE username = ?"
    result = query_db(query, (username,), True)
    
    # Verify password using secure hashing
    if result is None or not check_password_hash(result[3], password):
        # Track failed login attempt
        if client_ip not in failed_attempts:
            failed_attempts[client_ip] = []
        failed_attempts[client_ip].append(time.time())
        # Limit the size of the list to prevent memory issues
        if len(failed_attempts[client_ip]) > 10:
            failed_attempts[client_ip] = failed_attempts[client_ip][-10:]
            
        # Log failed attempt with sanitized username to prevent log injection
        logging.warning(f"Failed login attempt for username: {re.sub(r'[^\w]', '', username)}")
        return jsonify({"bad_login": True}), 400
        
    # Successful login - reset failed attempts
    if client_ip in failed_attempts:
        failed_attempts.pop(client_ip)
        
    # Store user info in session
    session["user_info"] = (result[0], result[1], result[2])
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
