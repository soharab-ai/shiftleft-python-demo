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
    
    # Added input validation to ensure username follows expected pattern
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return jsonify({"error": "Invalid username format"}), 400
        
    # Using ORM instead of raw SQL for better security and abstraction
    user = User.query.filter_by(username=username).first()
    
    # Checking hashed password instead of plaintext
    if user is None or not check_password_hash(user.password_hash, password):
        return jsonify({"bad_login": True}), 400
        
    # Using Flask-Login for session management
    login_user(user)
    
    # Also storing additional information in session for backward compatibility
    session["user_info"] = (user.id, user.username, user.access_level)
    
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
