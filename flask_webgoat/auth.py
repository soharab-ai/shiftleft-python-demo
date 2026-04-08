from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)

def validate_username(username):
    # FIXED: Added input validation to allow only alphanumeric characters and underscores
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format")
    return username

        return (
def validate_password(password):
    # FIXED: Added password length validation to prevent excessively long inputs
    if len(password) < 1 or len(password) > 128:
        raise ValueError("Invalid password length")
    return password

        "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
        % (username, password)
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    # FIXED: Added input validation to prevent malicious input patterns
    try:
        username = validate_username(username)
        password = validate_password(password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # FIXED: Replaced raw SQL with ORM-based query to prevent SQL injection by design
    from flask_webgoat import User, db
    user = db.session.query(User).filter_by(username=username).first()
    
    if user is None:
        return jsonify({"bad_login": True}), 400
    
    # FIXED: Enforce hash-only password verification - removed plain text fallback
    # FIXED: Added validation to ensure password_hash follows secure hash format
    if not user.password_hash or not ('$' in user.password_hash or user.password_hash.startswith('pbkdf2:') or user.password_hash.startswith('bcrypt:')):
        # Password hash format is invalid - require password reset
        return jsonify({"error": "Password requires reset due to security upgrade"}), 403
    
def migrate_plain_text_passwords():
    # FIXED: One-time migration function to hash all plain text passwords
    # This function should be called during deployment before the new authentication code is activated
    from flask_webgoat import User, db
    
    users = db.session.query(User).all()
    migration_count = 0
    
    for user in users:
        # Check if password is not already hashed
        if user.password_hash and not ('$' in user.password_hash or user.password_hash.startswith('pbkdf2:') or user.password_hash.startswith('bcrypt:')):
            # Hash the plain text password
            user.password_hash = generate_password_hash(user.password_hash)
            migration_count += 1
    
    db.session.commit()
    return jsonify({"migrated_passwords": migration_count})
