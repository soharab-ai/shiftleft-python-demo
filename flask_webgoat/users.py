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
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    
    if username is None or password is None or access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Added comprehensive input validation
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return jsonify({"error": "Username must be 3-20 characters and contain only letters, numbers, and underscores"}), 400
    
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    try:
        # Convert access_level to int and validate
        access_level_int = int(access_level)
        if access_level_int < 0:
            return jsonify({"error": "access_level must be a non-negative integer"}), 400
    except ValueError:
        return jsonify({"error": "access_level must be a valid integer"}), 400

    try:
        # Using SQLAlchemy ORM for safer database operations
        Base = declarative_base()
        
        class User(Base):
            __tablename__ = 'user'
            id = Column(Integer, primary_key=True)
            username = Column(String, unique=True)
            password = Column(String)
            access_level = Column(Integer)
        
        # Create engine and session
        engine = create_engine('sqlite:///instance/db.sqlite3')
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        
        # Create new user through ORM
        new_user = User(
            username=username,
            password=hashed_password,
            access_level=access_level_int
        )
        
        db_session.add(new_user)
        db_session.commit()
        db_session.close()
        
        return jsonify({"success": True})
    except Exception as err:
        # Fallback to using parameterized query if ORM setup fails
        try:
            # Hash password for security
            hashed_password = generate_password_hash(password)
            
            # Use parameterized query with explicit prepared statement
            conn = sqlite3.connect('instance/db.sqlite3')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)",
                (username, hashed_password, access_level_int)
            )
            conn.commit()
            conn.close()
            return jsonify({"success": True})
        except sqlite3.Error as sql_err:
            return jsonify({"error": "could not create user: " + str(sql_err)}), 500

