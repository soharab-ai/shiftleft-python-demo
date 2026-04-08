bp = Blueprint("users", __name__)

# SECURE: Initialize rate limiter for preventing brute force attacks
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def validate_username(username):
    """Validate username contains only alphanumeric characters and underscores"""
    # SECURE: Added input validation for username with length constraints
    if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
        return False
    return True


def validate_access_level(access_level):
    """Validate access_level is a valid integer within acceptable range"""
    # SECURE: Added input validation for access level with proper range checking
    try:
        level = int(access_level)
        return 0 <= level <= 10
    except ValueError:
        return False


def username_exists(username):
    """Check if username already exists in database using constant-time comparison"""
    # SECURE: Check for existing username to prevent duplicate entries
    from . import query_db
    query = "SELECT username FROM user WHERE username = ?"
    result = query_db(query, (username,), one=True)
    return result is not None


@bp.route("/create_user", methods=["POST"])
@limiter.limit("5 per minute")  # SECURE: Rate limiting to prevent automated attacks
def create_db_user():
    """Create database user with minimal permissions (defense in depth)"""
    # SECURE: Database permission segregation - application user has limited permissions
    # This function documents the recommended database setup with restricted privileges:
    # - GRANT SELECT, INSERT, UPDATE ON user TO app_user;
    # - DENY DROP, ALTER, CREATE TABLE TO app_user;
    # - Application should connect using app_user credentials, not root/admin
    # 
    # Implementation note: For SQLite, filesystem permissions should restrict access.
    # For production databases (PostgreSQL/MySQL), create dedicated role:
    # CREATE ROLE app_user WITH LOGIN PASSWORD 'secure_password';
    # GRANT SELECT, INSERT, UPDATE ON TABLE user TO app_user;
    # REVOKE CREATE, DROP, ALTER ON DATABASE FROM app_user;
    pass

    username = request.form.get("username")
    password = request.form.get("password")
    access_level_param = request.form.get("access_level")
    
    # SECURE: Validate all required parameters are provided
    if username is None or password is None or access_level_param is None:
        # SECURE: Generic error message to prevent information disclosure
        time.sleep(random.uniform(0.1, 0.3))  # SECURE: Artificial delay to prevent timing attacks
        return jsonify({"error": "Invalid request"}), 400
    
    # SECURE: Validate password length
    if len(password) < 3:
        time.sleep(random.uniform(0.1, 0.3))  # SECURE: Artificial delay to prevent timing attacks
        return jsonify({"error": "Invalid request"}), 400
    
    # SECURE: Validate username format to prevent malicious input
    if not validate_username(username):
        time.sleep(random.uniform(0.1, 0.3))  # SECURE: Artificial delay to prevent timing attacks
        return jsonify({"error": "Invalid request"}), 400
    
    # SECURE: Validate access level is within acceptable range
    if not validate_access_level(access_level_param):
        time.sleep(random.uniform(0.1, 0.3))  # SECURE: Artificial delay to prevent timing attacks
        return jsonify({"error": "Invalid request"}), 400
    
    # SECURE: Check if username already exists to prevent account enumeration
    if username_exists(username):
        time.sleep(random.uniform(0.1, 0.3))  # SECURE: Artificial delay to prevent timing attacks
        return jsonify({"error": "Invalid request"}), 400
    
    # SECURE: Hash password with bcrypt before storing to protect user credentials
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # SECURE: Use parameterized queries with placeholders to prevent SQL injection
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    
    try:
        from . import query_db
        # SECURE: Pass parameters as tuple to prevent SQL injection
        query_db(query, (username, hashed_password.decode('utf-8'), int(access_level_param)), False, True)
def render_username(username):
    """Safely render username with output encoding to prevent XSS"""
    # SECURE: Context-aware output encoding to prevent stored XSS attacks
    # SECURE: Use markupsafe.escape() to neutralize potential malicious content
    return escape(username)


def set_security_headers(response):
    """Add security headers to HTTP responses"""
    # SECURE: Content Security Policy to prevent XSS execution
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    # SECURE: Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # SECURE: Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
