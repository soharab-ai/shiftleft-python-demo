import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    # Initialize Flask-Bcrypt for password hashing
    bcrypt = Bcrypt()
    
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
    
    # Added username validation using regex to prevent SQL injection
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "username contains invalid characters"}), 400
    
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )

    # Input validation for access_level
    try:
        access_level_int = int(access_level)
        if access_level_int < 0:
            return jsonify({"error": "access_level must be a non-negative integer"}), 400
    except ValueError:
        return jsonify({"error": "access_level must be a valid integer"}), 400

    # Hash password using bcrypt before storing in database
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        # Using SQLAlchemy ORM approach
        Base = declarative_base()
        
        class User(Base):
            __tablename__ = 'user'
            id = Column(Integer, primary_key=True)
            username = Column(String, unique=True)
            password = Column(String)
            access_level = Column(Integer)
        
        # Create engine and session
        engine = create_engine('sqlite:///instance/db.sqlite')
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Create new user object
        new_user = User(username=username, password=hashed_password, access_level=access_level_int)
        db_session.add(new_user)
        db_session.commit()
        db_session.close()
        
        return jsonify({"success": True})
        
    except Exception as err:
        # Fallback to prepared statement if ORM approach fails
        try:
            conn = get_db_connection()
            # Using prepared statement for extra security
            stmt = conn.prepare("INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)")
            stmt.execute(username, hashed_password, access_level_int)
            conn.commit()
            return jsonify({"success": True})
        except sqlite3.Error as err:
            return jsonify({"error": f"could not create user: {str(err)}"})

