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

    from urllib.parse import urlparse, unquote

    def is_safe_url(url):
        # Check if the URL belongs to trusted domains
        allowed_domains = {'example.com', 'subdomain.example.com'}
        try:
            # Normalize URL to prevent encoding bypass
            url = unquote(url)
            parsed = urlparse(url)
            
            # Enforce protocol security
            if parsed.scheme and parsed.scheme not in ['http', 'https']:
                return False
                
            # Extract domain without port for comparison
            domain = parsed.netloc.split(':')[0] if parsed.netloc else ''
            
            # Check if domain exactly matches or is a subdomain of allowed domains
            is_allowed = any(domain == d or domain.endswith('.' + d) for d in allowed_domains)
            
            # Allow relative URLs (no netloc and no scheme)
            is_relative = not parsed.netloc and not parsed.scheme
            
            return is_allowed or is_relative
        except:
            return False

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        # Validate URL before redirect
        if url and is_safe_url(url):
            return redirect(url)
        else:
            # Default to a safe location if URL is invalid
            return redirect('/login')
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})

