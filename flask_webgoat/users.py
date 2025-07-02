import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Setup SQLAlchemy
Base = declarative_base()
db = SQLAlchemy()

# User model
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    access_level = db.Column(db.Integer, nullable=False)

def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        logger.warning("Create user attempt with no user_info in session")
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        logger.warning(f"Unauthorized create user attempt with access level {access_level}")
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_input = request.form.get("access_level")
    
    if username is None or password is None or access_level_input is None:
        logger.warning("Create user attempt with missing parameters")
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Input validation for username using regex
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        logger.warning(f"Invalid username format attempted: {username[:10]}...")
        return jsonify({"error": "Invalid username format. Use only alphanumeric characters and underscore"}), 400
    
    if len(password) < 3:
        logger.warning("Create user attempt with password too short")
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )

    # Input validation for access_level
    try:
        access_level_int = int(access_level_input)
        if access_level_int < 0:
            logger.warning(f"Invalid access level attempted: {access_level_input}")
            return jsonify({"error": "access_level must be a non-negative integer"}), 400
    except ValueError:
        logger.warning(f"Non-integer access level attempted: {access_level_input}")
        return jsonify({"error": "access_level must be a valid integer"}), 400
    
    # Hash password before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        # Approach 1: Using ORM
        new_user = User(
            username=username,
            password=hashed_password,
            access_level=access_level_int
        )
        
        # Start a transaction
        db_session = db.session
        try:
            db_session.add(new_user)
            db_session.commit()
            logger.info(f"User created successfully: {username}")
            return jsonify({"success": True})
        except Exception as e:
            db_session.rollback()
            logger.error(f"Database error when creating user: {str(e)}")
            return jsonify({"error": "could not create user: database error"})
            
    except Exception as e:
        # Fallback to raw SQL with parameterized query if ORM approach fails
        logger.warning(f"ORM approach failed, falling back to raw SQL: {str(e)}")
        
        # Using parameterized query with explicit connection management
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            
            # Start transaction
            conn.execute('BEGIN TRANSACTION')
            
            # Execute parameterized query
            cursor.execute(
                "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)",
                (username, hashed_password, access_level_int)
            )
            
            # Commit transaction
            conn.commit()
            conn.close()
            
            logger.info(f"User created successfully (SQL fallback): {username}")
            return jsonify({"success": True})
            
        except sqlite3.Error as err:
            # Rollback transaction if error occurs
            if conn:
                conn.rollback()
                conn.close()
            logger.error(f"SQL error when creating user: {str(err)}")
            return jsonify({"error": "could not create user: " + str(err)})
