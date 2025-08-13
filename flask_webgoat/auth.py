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

from urllib.parse import urlparse
import re
import secrets

# Define allowed domains (should be configured in application settings)
ALLOWED_DOMAINS = {'example.com', 'yourdomain.com'}
# Define allowed path patterns (regex)
ALLOWED_PATH_PATTERNS = [r'^/[a-zA-Z0-9_\-/]+$']

def is_safe_url(url):
    if not url:
        return False
    parsed_url = urlparse(url)
    
    # Check if it's a relative URL or from trusted domains
    if parsed_url.netloc and parsed_url.netloc not in ALLOWED_DOMAINS:
        return False
    
    # Validate path structure for additional security
    path = parsed_url.path
    if path:
        path_valid = any(re.match(pattern, path) for pattern in ALLOWED_PATH_PATTERNS)
        if not path_valid:
            return False
            
    return True

query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
if result is None:
    # Log failed redirect attempt
    app.logger.warning(f"Potential redirect attempt to: {url}")
    
    # Fixed: Validate URL before redirecting
    if url and is_safe_url(url):
        # For external domains, use intermediate warning page
        parsed_url = urlparse(url)
        if parsed_url.netloc in ALLOWED_DOMAINS:
            return redirect(url_for('external_redirect', destination=url, token=secrets.token_urlsafe()))
        return redirect(url)
    else:
        # Default to a safe page if URL is not valid
        return redirect(url_for('login', error="Invalid credentials"))
        
session["user_info"] = (result[0], result[1], result[2])
return jsonify({"success": True})

