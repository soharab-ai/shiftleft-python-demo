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

    # Define whitelist of allowed domains
    ALLOWED_DOMAINS = ['example.com', 'api.example.com']
    
    # Define a dictionary of allowed redirect endpoints
    ALLOWED_REDIRECTS = {
        'home': '/home',
        'profile': '/profile',
        'settings': '/settings',
        'default': '/login'
    }
    
    # Valid paths for relative URLs
    VALID_PATHS = ['/home', '/profile', '/settings', '/login', '/dashboard']
    
    def is_safe_url(url):
        # Check if URL is None or empty
        if url is None or not url:
            return False
        
        # Normalize URL before validation to prevent encoding bypass attacks
        url = unquote(url)
        
        # Parse URL using werkzeug's more secure URL parsing
        parsed_url = url_parse(url)
        
        # Check URL scheme - only allow http and https
        safe_schemes = ['http', 'https', '']
        if parsed_url.scheme and parsed_url.scheme not in safe_schemes:
            return False
            
        # For absolute URLs, validate domain
        if parsed_url.netloc:
            return is_domain_allowed(parsed_url.netloc)
        else:
            # For relative URLs, prevent path traversal and restrict to known paths
            if '..' in url or url.startswith('//'):
                return False
            # Ensure the relative URL starts with one of our valid paths
            return any(url.startswith(path) for path in VALID_PATHS)
    
    def is_domain_allowed(domain):
        # More precise domain matching
        return domain in ALLOWED_DOMAINS or any(domain.endswith('.' + d) for d in ALLOWED_DOMAINS)
    
    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        # Fixed vulnerability: Open Redirect - Implement comprehensive URL validation
        if url and is_safe_url(url):
            return redirect(url)
        else:
            # Use mapping approach as additional security
            redirect_key = request.args.get('redirect', 'default')
            safe_url = ALLOWED_REDIRECTS.get(redirect_key, '/login')
            return redirect(safe_url)
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})

