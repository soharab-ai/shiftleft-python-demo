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

query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
if result is None:
    # Fix for Open Redirect vulnerability - Validate URL before redirecting
    # Option 1: Always redirect to a safe default page
    return redirect(url_for('login', next=url))
    
    # Option 2: If you must allow external URLs, validate them thoroughly
    # allowed_domains = ['trusted-domain.com', 'another-trusted.org']
    # if url and (url.startswith('/') or 
    #            (validators.url(url) and 
    #             urlparse(url).netloc in allowed_domains)):
    #     return redirect(url)
    # else:
    #     return redirect(url_for('login'))
session["user_info"] = (result[0], result[1], result[2])
return jsonify({"success": True})

