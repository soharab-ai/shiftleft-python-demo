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
# Create a security logger
security_logger = logging.getLogger('security')

# Dictionary to track failed redirect attempts for rate limiting
failed_redirect_attempts = None

def validate_redirect_url(url):
    """Validate if a URL is safe to redirect to based on domain whitelist and other security checks"""
    try:
        # Normalize the URL first to prevent encoding bypass techniques
        normalized_url = urllib.parse.unquote(url)
        parsed_url = urllib.parse.urlparse(normalized_url)
        
        # Validate URL scheme (only allow http/https)
        if parsed_url.scheme not in ['', 'http', 'https']:
            security_logger.warning(f"Rejected redirect with invalid scheme: {parsed_url.scheme}")
            return False
            
        # List of allowed domains (exact matches with proper boundary checks)
        allowed_domains = ['example.com', 'subdomain.example.com']
        
        # Allow relative URLs (no netloc) or URLs with allowed domains
        if not parsed_url.netloc:
            return True
            
        # Check for exact domain matches (with proper boundary checking)
        domain_match = any(parsed_url.netloc == domain or 
                          parsed_url.netloc.endswith('.' + domain) for domain in allowed_domains)
        
        if not domain_match:
            security_logger.warning(f"Rejected redirect to non-allowed domain: {parsed_url.netloc}")
            return False
            
        return True
    except Exception as e:
        security_logger.error(f"Error validating redirect URL: {str(e)}")
        return False

def generate_url_signature(url, secret_key="APP_SECRET_KEY"):
    """Generate a signature for a URL to prevent tampering"""
    return hashlib.sha256(f"{url}{secret_key}".encode()).hexdigest()

def verify_url_signature(url, signature, secret_key="APP_SECRET_KEY"):
    """Verify the signature of a URL"""
    expected = generate_url_signature(url, secret_key)
    return compare_digest(signature, expected)

def rate_limit_check(ip_address):
    """Check if an IP is rate limited for redirect attempts"""
    current_time = time.time()
    if ip_address in failed_redirect_attempts:
        attempts = [t for t in failed_redirect_attempts[ip_address] if t > current_time - 3600]  # 1 hour window
        failed_redirect_attempts[ip_address] = attempts
        
        if len(attempts) >= 5:  # Allow 5 attempts per hour
            security_logger.warning(f"Rate limit reached for IP {ip_address} attempting redirects")
            return False
            
    return True

def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    ip_address = request.remote_addr
    
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )
    
    # Validate redirect URL regardless of authentication status
    if not validate_redirect_url(url):
        # Track failed redirect attempt for rate limiting
        if ip_address not in failed_redirect_attempts:
            failed_redirect_attempts[ip_address] = []
        failed_redirect_attempts[ip_address].append(time.time())
        
        # Check rate limiting
        if not rate_limit_check(ip_address):
            return jsonify({"error": "Too many invalid redirect attempts"}), 429
            
        return jsonify({"error": "Invalid redirect URL"}), 400

    # Continue with authentication
    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    
    if result is None:
        security_logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    session["user_info"] = (result[0], result[1], result[2])
    
    # Generate URL signature for the redirect
    signature = generate_url_signature(url)
    
    # For external URLs, redirect through a warning page
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.netloc and parsed_url.netloc != request.host:
        return redirect(url_for('auth.external_redirect', 
                               target_url=url, 
                               signature=signature))
    
    # For internal URLs, redirect directly
    return redirect(url)

# Add this method to create a warning page for external redirects
def external_redirect():
    target_url = request.args.get('target_url')
    signature = request.args.get('signature')
    
    if not target_url or not signature:
        return jsonify({"error": "Missing parameters"}), 400
        
    if not verify_url_signature(target_url, signature):
        security_logger.warning(f"Invalid URL signature for external redirect: {target_url}")
        return jsonify({"error": "Invalid URL signature"}), 400
    
    if not validate_redirect_url(target_url):
        return jsonify({"error": "Invalid redirect URL"}), 400
        
    # Render a warning template that informs users they're leaving the site
    return render_template('external_redirect.html', target_url=target_url)


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
