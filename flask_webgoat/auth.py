from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@limiter.limit("5 per minute")  # Added rate limiting to prevent brute force attacks
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )
    
    # Added input validation for username to prevent malicious inputs
    if not re.match(r'^[a-zA-Z0-9_-]{3,16}$', username):
        return jsonify({"error": "Invalid username format"}), 400
        
    # Using SQLAlchemy ORM instead of raw SQL queries for better security
    user = User.query.filter_by(username=username).first()
    
    if user is None:
        return jsonify({"bad_login": True}), 400
        
    # Verify password hash instead of comparing plaintext passwords
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
        return jsonify({"bad_login": True}), 400
        
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
