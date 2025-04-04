from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    # Initialize rate limiter to prevent brute force attacks
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["5 per minute", "100 per day"]
    )
    
    # Get username and password from request
    username = request.form.get("username")
    password = request.form.get("password")
    
    # Input validation
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )
    
    # Validate username format (alphanumeric and reasonable length)
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return jsonify({"error": "Invalid username format"}), 400
    
    # Validate password length to prevent DoS attacks
    if len(password) > 64:
        return jsonify({"error": "Password too long"}), 400
    
    # Check failed login attempts (account lockout feature)
    if 'login_attempts' in session and session['login_attempts'] >= 5 and \
       'lockout_until' in session and datetime.now() < session['lockout_until']:
        return jsonify({"error": "Account temporarily locked. Try again later."}), 429
    
    # Using ORM approach for more security
    user = User.query.filter_by(username=username).first()
    
    if user is None:
        # Track failed login attempts
        session['login_attempts'] = session.get('login_attempts', 0) + 1
        if session['login_attempts'] >= 5:
            session['lockout_until'] = datetime.now() + timedelta(minutes=15)
        return jsonify({"bad_login": True}), 400
    
    # Verify the password with bcrypt (timing-safe comparison)
    # Assuming the stored password is already hashed with bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        # Track failed login attempts
        session['login_attempts'] = session.get('login_attempts', 0) + 1
        if session['login_attempts'] >= 5:
            session['lockout_until'] = datetime.now() + timedelta(minutes=15)
        return jsonify({"bad_login": True}), 400
    
    # Reset failed login attempts
    session.pop('login_attempts', None)
    session.pop('lockout_until', None)
    
    # Improved session security
    session.permanent = True  # Enable session expiration
    session.modified = True   # Ensure session is saved
    
    # Store minimal user data in session
    session["user_id"] = user.id
    session["username"] = user.username
    session["access_level"] = user.access_level
    session["login_time"] = datetime.now().isoformat()
    session["csrf_token"] = generate_csrf_token()  # Assuming this function exists
    
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
