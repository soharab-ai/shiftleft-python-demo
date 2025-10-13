from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
# Dictionary to track failed login attempts
failed_attempts = null
# Lock duration in seconds (5 minutes)
LOCK_DURATION = 300
# Maximum allowed attempts before lockout
MAX_ATTEMPTS = 5

def login():
    username = request.form.get("username")
    password = request.form.get("password")
    client_ip = request.remote_addr
    
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    # Check for account lockout due to brute force attempts
    current_time = time.time()
    attempt_key = f"{username}:{client_ip}"
    
    if attempt_key in failed_attempts:
        attempts_data = failed_attempts[attempt_key]
        if attempts_data["count"] >= MAX_ATTEMPTS:
            if current_time - attempts_data["timestamp"] < LOCK_DURATION:
                # Log suspicious activity
                logging.warning(f"Blocked login attempt for locked account: {username} from IP: {client_ip}")
                return jsonify({"error": "Account temporarily locked. Try again later."}), 429
            else:
                # Reset counter after lock period
                failed_attempts.pop(attempt_key)
    
    # Use parameterized query to prevent SQL injection, only fetch username and hashed password
    query = "SELECT id, username, password_hash, access_level FROM user WHERE username = ?"
    user = query_db(query, (username,), True)
    
    # Verify password and manage authentication
    if user is None or not check_password_hash(user[2], password):
        # Handle failed login
        if attempt_key in failed_attempts:
            failed_attempts[attempt_key]["count"] += 1
            failed_attempts[attempt_key]["timestamp"] = current_time
        else:
            failed_attempts[attempt_key] = {"count": 1, "timestamp": current_time}
            
        # Log failed attempt
        logging.warning(f"Failed login attempt for user: {username} from IP: {client_ip}")
        return jsonify({"bad_login": True}), 400
        
    # Successful login - reset failed attempts
    if attempt_key in failed_attempts:
        failed_attempts.pop(attempt_key)
    
    # Create secure session with proper user information
    session["user_info"] = (user[0], user[1], user[3])  # id, username, access_level
    session["authenticated_at"] = current_time
    session["expires_at"] = current_time + 3600  # 1-hour expiration
    
    # Set secure session options
    session.permanent = True
    
    # Log successful login
    logging.info(f"Successful login: {username} from IP: {client_ip}")
    
    return jsonify({"success": True})

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
