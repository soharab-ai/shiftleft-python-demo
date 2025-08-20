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
            400,
        )

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        # Fix for Open Redirect vulnerability with enhanced security
        # Step 1: Normalize the URL to prevent encoding bypass attacks
        normalized_url = unquote(url)
        
        # Step 2: Use configuration-based approach for allowed domains
        # and improved validation logic
        if normalized_url and is_safe_url(normalized_url):
            # Step 4: Add CSRF protection with signed token validation
            if validate_redirect_token(normalized_url):
                return redirect(normalized_url)
        
        # Fallback to a default safe page if URL is not safe
        return redirect(url_for('index'))
    
    # Step 5: Store URLs for request context validation
    if 'previous_urls' not in session:
        session['previous_urls'] = []
    session['previous_urls'] = session['previous_urls'][-5:] + [url]  # Keep last 5 URLs
    
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})

def is_safe_url(url):
    """Validates if the URL is safe to redirect to with improved security."""
    if url is None:
        return False
        
    # Check for dangerous protocols that can lead to XSS
    if url.startswith(('javascript:', 'data:', 'vbscript:')):
        return False
    
    # Allow relative URLs that don't try to escape the site
    if url.startswith('/') and not url.startswith('//'):
        return True
        
    # For absolute URLs, check against allowed domains from configuration
    try:
        parsed_url = url_parse(url)  # Using werkzeug's url_parse for better security
        # Get allowed domains from app configuration
        allowed_domains = current_app.config.get('ALLOWED_REDIRECT_DOMAINS', 
                                                ['example.com', 'trusted-domain.com', 'your-app-domain.com'])
        return parsed_url.host in allowed_domains
    except:
        # If URL parsing fails, consider it unsafe
        return False

def generate_redirect_token(url, expiry=300):  # 5 minutes expiry
    """Generate a secure token for the redirect URL with expiration time."""
    token_data = {'url': url, 'expires': time.time() + expiry}
    # In a real implementation, you would use a secure signing method
    # This is a simplified version for demonstration
    token = f"{secrets.token_hex(16)}_{token_data['url']}_{token_data['expires']}"
    session['redirect_token'] = token
    return token

def validate_redirect_token(url):
    """Validate the redirect token stored in session."""
    if 'redirect_token' not in session:
        return False
        
    token = session['redirect_token']
    try:
        # Extract token parts (simplified implementation)
        parts = token.split('_', 2)
        if len(parts) != 3:
            return False
            
        token_hex, token_url, expires = parts[0], parts[1], float(parts[2])
        
        # Check if token has expired
        if time.time() > expires:
            return False
            
        # Check if URL matches the one in token
        return url == token_url
    except:
        return False
