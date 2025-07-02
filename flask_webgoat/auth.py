from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    # Input validation for username format
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Invalid username format"}), 400
    
    try:
        # Using SQLAlchemy ORM instead of raw SQL queries
        from models import User, db
        
        # Using ORM with result limiting to prevent resource exhaustion
        user = User.query.filter_by(username=username).limit(1).first()
        
        # Proper password verification with timing attack protection
        if user is None or not check_password_hash(user.password_hash, password):
            # Avoid revealing which field was incorrect
            return jsonify({"bad_login": True}), 400
            
        # Store user info in session
        session["user_info"] = (user.id, user.username, user.access_level)
        
        # Optional: record successful login attempt for audit purposes
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"success": True})
        
    except SQLAlchemyError as e:
        # Secure error logging without exposing sensitive details
        # Log the error securely here
        return jsonify({"error": "Database error occurred"}), 500

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
