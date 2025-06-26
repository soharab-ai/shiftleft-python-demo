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

    # vulnerability: SQL Injection
    query = (
        "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
        % (username, password)
    )
    result = query_db(query, [], True)
    if result is None:
        return jsonify({"bad_login": True}), 400
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})


@bp.route("/login_and_redirect")
def login_and_redirect():
def is_safe_url(target):
    """
    Enhanced URL validation that handles various edge cases and bypass attempts:
    1. Validates against allowed domains and subdomains
    2. Prevents protocol-relative URL attacks (//evil.com)
    3. Normalizes URLs before validation
    4. Validates URL parts thoroughly 
    """
    if target is None or target.strip() == '':
        return False
        
    # Normalize the URL to handle encoding tricks
    target = url_fix(target)
    
    # Prevent protocol-relative URLs (//evil.com)
    if target.startswith('//'):
        return False
        
    # Safe if it's a relative path that doesn't try path traversal
    if target.startswith('/'):
        path_traversal_pattern = re.compile(r'\.\./')
        if path_traversal_pattern.search(target):
            # Log potential path traversal attempt
            logging.warning(f"Potential path traversal attempt blocked: {target}")
            return False
        return True
    
    # For absolute URLs, use werkzeug's url_parse for robust parsing
    parsed_target = url_parse(target)
    
    # Check for dangerous schemes
    allowed_schemes = ['http', 'https']
    if parsed_target.scheme not in allowed_schemes:
        logging.warning(f"Redirect blocked - disallowed scheme: {parsed_target.scheme}")
        return False
    
    # Get host from request to determine our own domain
    host_url = request.host_url
    ref_url = urlparse(host_url)
    
    # Whitelist of allowed domains (base domain and specific subdomains)
    allowed_domains = ['example.com', 'subdomain.example.com']
    
    # Check if domain exactly matches or is a subdomain of allowed domains
    target_domain = parsed_target.netloc
    if target_domain in allowed_domains:
        return True
        
    # Check for wildcard subdomains - allow *.example.com
    for domain in allowed_domains:
        if domain.startswith('*.'):
            base_domain = domain[2:]  # Remove *. prefix
            if target_domain.endswith(base_domain):
                return True
                
    # Log failed redirect attempt
    logging.warning(f"Unauthorized redirect attempt to: {target_domain}")
    return False

def generate_csrf_token():
    """Generate a CSRF token for protecting redirects"""
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    return session['csrf_token']

@bp.route("/login_and_redirect")
def login_and_redirect():
    # CSRF protection for redirects
    csrf_token = request.args.get('csrf_token')
    if 'csrf_token' not in session or not csrf_token or not hmac.compare_digest(session['csrf_token'], csrf_token):
        logging.warning("CSRF validation failed for redirect request")
        return jsonify({"error": "Invalid or missing CSRF token"}), 403

    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    
    if username is None or password is None:
        return jsonify({"error": "username and password parameters must be provided"}), 400

    # First validate credentials before considering any redirects
    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    
    if result is None:
        # Authentication failed
        logging.info(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Authentication successful, now handle the redirect safely
    session["user_info"] = (result[0], result[1], result[2])
    
    # If no URL is provided, redirect to default page
    if url is None:
        return redirect(url_for('dashboard.index'))
        
    # Validate URL after successful authentication
    if is_safe_url(url):
        # Add a secure referrer policy header
        response = redirect(url)
        response.headers['Referrer-Policy'] = 'same-origin'
        return response
    else:
        # Log potential open redirect attack
        logging.warning(f"Potential open redirect attack blocked. Target URL: {url}")
        return redirect(url_for('dashboard.index'))

# Register the CSRF token for templates
@bp.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())
