import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_str = request.form.get("access_level")
    
    # Check if all required parameters are provided
    if username is None or password is None or access_level_str is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Validate password length
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    # Added input validation for username format
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username contains invalid characters"}), 400
    
    # Added validation for access_level
    try:
        access_level = int(access_level_str)
        if access_level not in [0, 1, 2]:  # Define allowed access levels
            raise ValueError
    except ValueError:
        return jsonify({"error": "Invalid access level"}), 400
    
    # Added password hashing for security
    hashed_password = generate_password_hash(password)
    
    # Using parameterized query to prevent SQL injection
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    params = (username, hashed_password, access_level)

    try:
        query_db(query, params, False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        # Added comprehensive error handling to avoid information leakage
        logging.error(f"Database error while creating user: {str(err)}")
        return jsonify({"error": "An error occurred while creating the user"}), 500

    # Username format validation using regex
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Invalid username format"}), 400
    
    # Access level validation
    try:
        user_access_level = int(user_access_level)
        if user_access_level < 0 or user_access_level > 2:  # Assuming valid access levels are 0, 1, 2
            return jsonify({"error": "Invalid access level value"}), 400
    except ValueError:
        return jsonify({"error": "Access level must be a number"}), 400
    
    try:
        # Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Use ORM approach instead of raw SQL
        Base = declarative_base()
        
        class User(Base):
            __tablename__ = 'user'
            id = Column(Integer, primary_key=True)
            username = Column(String, unique=True, nullable=False)
            password = Column(String, nullable=False)
            access_level = Column(Integer, nullable=False)
            __table_args__ = (UniqueConstraint('username', name='unique_username'),)
        
        # Create new user with ORM
        db_session = db.session
        new_user = User(
            username=username,
            password=hashed_password,
            access_level=user_access_level
        )
        
        db_session.add(new_user)
        db_session.commit()
        
        return jsonify({"success": True})
    except Exception as err:
        db_session.rollback()  # Rollback transaction on error
        return jsonify({"error": f"Could not create user: {str(err)}"})
