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
# Configuration settings should be in app config, moved here for demonstration
ALLOWED_DOMAINS = {'example.com', 'www.example.com', 'secure.example.com'}
REDIRECT_EXPIRY_SECONDS = 300  # 5 minutes
SIGNED_REDIRECTS = null  # Store for signed redirects with expiry
logger = logging.getLogger(__name__)

# Setup rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def is_safe_url(url):
    """Enhanced URL validation that checks protocol, domain, and normalizes URLs"""
    if not url:
        return False
    
    # Handle relative URLs - must start with / and not contain ..
    if url.startswith('/'):
        if '..' in url:
            logger.warning(f"Path traversal attempt detected in URL: {url[:100]}")
            return False
        return True
    
    # Validate URL format using validators library
    if not validators.url(url):
        return False
    
    # Check for dangerous schemes
    parsed_url = urlparse(url)
    dangerous_schemes = ['javascript', 'data', 'file', 'vbscript']
    if parsed_url.scheme.lower() in dangerous_schemes:
        logger.warning(f"Dangerous URL scheme detected: {parsed_url.scheme}")
        return False
    
    # Validate against allowed domains
    return parsed_url.netloc in ALLOWED_DOMAINS

def generate_signed_redirect(url):
    """Create a signed redirect URL with expiration"""
    if not is_safe_url(url):
        return None
        
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(seconds=REDIRECT_EXPIRY_SECONDS)
    SIGNED_REDIRECTS[token] = {
        'url': url,
        'expiry': expiry
    }
    return token

def verify_signed_redirect(token):
    """Verify a signed redirect token and return the URL if valid"""
    if token not in SIGNED_REDIRECTS:
        return None
        
    redirect_info = SIGNED_REDIRECTS[token]
    if datetime.now() > redirect_info['expiry']:
        # Clean up expired token
        del SIGNED_REDIRECTS[token]
        return None
        
    # Use the URL and remove from storage to prevent reuse
    url = redirect_info['url']
    del SIGNED_REDIRECTS[token]
    return url

@bp.route("/login_and_redirect")
@limiter.limit("10 per minute")  # Rate limiting for login attempts
def login_and_redirect():
    # Generate CSRF token if not present
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    
    # For GET requests, only accept the redirect URL and validate it
    if request.method == 'GET':
        url = request.args.get("url")
        if url and is_safe_url(url):
            # Store the pre-validated URL in session
            redirect_token = generate_signed_redirect(url)
            session['redirect_token'] = redirect_token
            return render_template('login.html', csrf_token=session['csrf_token'])
        else:
            return redirect(url_for('auth.login'))
    
    # For POST requests, handle authentication
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        logger.warning(f"CSRF validation failed from IP: {request.remote_addr}")
        return jsonify({"error": "CSRF validation failed"}), 400
    
    username = request.form.get("username")
    password = request.form.get("password")
    
    if username is None or password is None:
        return jsonify({"error": "Username and password must be provided"}), 400

    # Log authentication attempt with sanitized data
    logger.info(f"Login attempt for user: {username[:10]}..." if username else "None")
    
    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    
    if result is None:
        logger.warning(f"Failed login attempt for user: {username[:10]}...")
        return redirect(url_for('auth.login', error='invalid_credentials'))
    
    # Authentication successful
    session["user_info"] = (result[0], result[1], result[2])
    
    # Handle redirect if there's a valid token
    redirect_token = session.pop('redirect_token', None)
    if redirect_token:
        url = verify_signed_redirect(redirect_token)
        if url and is_safe_url(url):  # Double-check URL safety
            return redirect(url)
    
    # Default redirect to dashboard if no valid redirect URL
    return redirect(url_for('dashboard.index'))

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
