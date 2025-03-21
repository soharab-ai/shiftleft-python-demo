from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
# Initialize CSRF protection
csrf = CSRFProtect()

# Configure secure session settings
def configure_session_security(app):
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )

@limiter.limit("5/minute")
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "Invalid credentials"}),  # Generic error message for security
            400,
        )
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
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Fix: Store user session info after successful authentication
    session["user_info"] = (result[0], result[1], result[2])
    
    # Fix: Only perform URL validation and redirect after successful authentication
    if url:
        # Use dedicated function for URL validation
        safe_url = validate_redirect_url(url)
        return redirect(safe_url)
    
    return jsonify({"success": True})

def validate_redirect_url(url):
    """
    Validates and sanitizes redirect URLs to prevent open redirect vulnerabilities.
    """
    # Normalize the URL first to prevent bypass techniques
    url = normalize_url(url)
    
    # Check if it's a relative URL (safer approach)
    if url.startswith('/') and not url.startswith('//'):
        return url
        
    # For absolute URLs, use strict domain validation
    parsed_url = urlparse(url)
    # Fix: Use configuration for allowed domains instead of hardcoding
    allowed_domains = get_config('ALLOWED_REDIRECT_DOMAINS', ['example.com', 'trusted-site.com'])
    
    # Fix: Use exact domain matching to prevent subdomain attacks
    if parsed_url.netloc and any(parsed_url.netloc == domain for domain in allowed_domains):
        return url
        
    # Log potential redirect attack
    log_security_event(f"Blocked potential open redirect to: {url}")
    return get_default_redirect_url()

def normalize_url(url):
    """
    Normalizes URLs to prevent bypass techniques
    """
    # Basic normalization
    url = url.strip()
    # Additional normalization could be added here for specific bypass techniques
    return url

def get_config(key, default=None):
    """
    Retrieves configuration values
    """
    # In a real implementation, this would fetch from a config system
    # For now, just return the default
    return default

def log_security_event(message):
    """
    Logs security events securely
    """
    # Use proper sanitization to prevent log injection/forging
    safe_message = message.replace("\n", "\\n").replace("\r", "\\r")
    logging.warning(f"SECURITY EVENT: {safe_message}")

def get_default_redirect_url():
    """
    Returns a safe default redirect URL
    """
    return "/dashboard"

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
