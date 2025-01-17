import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form['username']
    password = request.form['password']
    access_level = request.form['access_level']

    if not username or not password or not access_level:
        return jsonify({"error": "username, password and access_level parameters have to be provided"}), 400

    if len(password) < 3:
        return jsonify({"error": "the password needs to be at least 3 characters long"}), 402

    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    args = (username, generate_password_hash(password), int(access_level))

    try:
        query_db(query, args, False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        return jsonify({"error": "could not create user:" + str(err)})

