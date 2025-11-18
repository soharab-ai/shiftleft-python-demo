import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Define SQLAlchemy model
Base = declarative_base()
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    access_level = Column(Integer, nullable=False)

# Create SQLAlchemy engine and session
engine = create_engine(Config.DATABASE_URI)
DBSession = sessionmaker(bind=engine)

# Define Pydantic model for validation
class UserCreate(BaseModel):
    username: constr(regex=r'^[a-zA-Z0-9_]+$')
    password: constr(min_length=3)
    access_level: int
    
    @validator('access_level')
    def validate_access_level(cls, v):
        if v not in [0, 1, 2]:
            raise ValueError('Access level must be 0, 1 or 2')
        return v

@limiter.limit("10 per minute")  # Implement rate limiting
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
        
    # Validate CSRF token to prevent CSRF attacks
    try:
        validate_csrf(request.form.get('csrf_token'))
    except BadRequest:
        return jsonify({"error": "CSRF validation failed"}), 400
        
    # Use Pydantic for comprehensive input validation
    try:
        user_data = UserCreate(
            username=request.form.get("username"),
            password=request.form.get("password"),
            access_level=int(request.form.get("access_level", 0))
        )
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
        
    # Hash password with bcrypt before storing
    hashed_password = bcrypt.hashpw(
        user_data.password.encode('utf-8'), 
        bcrypt.gensalt()
    ).decode('utf-8')
    
    try:
        # Use SQLAlchemy ORM instead of raw SQL queries
        db_session = DBSession()
        new_user = User(
            username=user_data.username,
            password=hashed_password,  # Store hashed password
            access_level=user_data.access_level
        )
        db_session.add(new_user)
        db_session.commit()
        db_session.close()
        return jsonify({"success": True})
    except Exception as err:
        return jsonify({"error": f"Could not create user: {str(err)}"})

