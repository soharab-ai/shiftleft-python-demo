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
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return jsonify({"error": "Invalid credentials"}), 401
        
    # Added rate limiting protection
    if is_rate_limited(username):
        return jsonify({"error": "Too many login attempts"}), 429
        
    # Modified query to only retrieve the hashed password
    query = "SELECT id, username, access_level, password_hash FROM user WHERE username = ?"
    result = query_db(query, [username], True)
    
    # Generic error message to avoid revealing too much information
    if result is None or not check_password_hash(result[3], password):
        return jsonify({"error": "Invalid credentials"}), 401
        
    # Store only necessary user information in session
    session["user_info"] = (result[0], result[1], result[2])
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
