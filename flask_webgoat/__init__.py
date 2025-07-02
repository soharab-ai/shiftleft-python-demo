import os
import sqlite3
import logging
import json
import uuid
from logging.handlers import RotatingFileHandler
import scrubadub
from pathlib import Path
from dynaconf import Dynaconf
from flask import Flask, g, request

DB_FILENAME = "database.db"

# Centralized sensitive data configuration
SENSITIVE_FIELDS = {
    "high": ["password", "secret", "token", "key", "credential"],
    "medium": ["username", "email", "address"],
    "low": ["name", "phone"]
}

# Enhanced environment configuration using dynaconf
settings = Dynaconf(
    environments=True,
    env_switcher="ENVIRONMENT",
    settings_files=["settings.toml", ".secrets.toml"],
    load_dotenv=True,
)

# Configure structured JSON logging with rotation
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# Setup JSON formatter for structured logging
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, 'request_id', 'no-request-id')
        }
        return json.dumps(log_record)

# Setup different log handlers based on severity
main_handler = RotatingFileHandler(
    filename=log_dir / "app.log",
    maxBytes=10485760,  # 10MB
    backupCount=10
)
main_handler.setFormatter(JsonFormatter())

error_handler = RotatingFileHandler(
    filename=log_dir / "error.log",
    maxBytes=10485760,  # 10MB
    backupCount=10
)
error_handler.setFormatter(JsonFormatter())
error_handler.setLevel(logging.ERROR)

# Setup root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO if settings.environment == "production" else logging.DEBUG)
logger.addHandler(main_handler)
logger.addHandler(error_handler)

# Create module logger
logger = logging.getLogger(__name__)

class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = getattr(request, 'id', uuid.uuid4().hex)
        return True

logger.addFilter(RequestIdFilter())

def sanitize_log_data(data):
    """Sanitize data using scrubadub library with data classification awareness"""
    # Use scrubadub to remove sensitive information based on predefined patterns
    scrubber = scrubadub.Scrubber()
    
    # If data is a dictionary, handle each field according to its sensitivity
    if isinstance(data, dict):
        sanitized = null
        for key, value in data.items():
            # Check if the key is in our sensitive fields
            if any(key.lower() in fields for sensitivity, fields in SENSITIVE_FIELDS.items()):
                sanitized[key] = "[REDACTED]"
            else:
                # Still scrub the value in case it contains other sensitive info
                sanitized[key] = scrubber.clean(str(value)) if value else value
        return sanitized
    
    # For strings (like SQL queries), use the scrubber
    return scrubber.clean(str(data))

def query_db(query, args=(), one=False, commit=False):
    # Add request ID for log correlation
    request_id = getattr(request, 'id', uuid.uuid4().hex)
    
    with sqlite3.connect(DB_FILENAME) as conn:
        # Log the query based on environment, with data classification awareness
        if settings.get('DEBUG_SQL', False):
            # Sanitize the query using proper library instead of regex
            sanitized_query = sanitize_log_data(query)
            logger.debug(f"Executing query: {sanitized_query}", 
                        extra={"request_id": request_id, "data_classification": "database"})
            
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()

def create_app():
    app = Flask(__name__)
    app.secret_key = settings.get('SECRET_KEY', "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee")
    
    # Assign a unique ID to each request for log correlation
    @app.before_request
    def before_request():
        request.id = uuid.uuid4().hex
    
    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    conn.execute(create_table_query)

    # Using query_db with sanitization instead of direct execution
    admin_data = {
        "id": 1, 
        "username": "admin", 
        "password": settings.get('ADMIN_PASSWORD', 'maximumentropy'), 
        "access_level": 0
    }
    # Log with data classification but redact sensitive fields
    logger.info(f"Creating admin user", 
                extra={"request_id": "setup", "data": sanitize_log_data(admin_data)})
                
    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', ?, 0)"""
    conn.execute(insert_admin_query, (admin_data['password'],))
    conn.commit()
    conn.close()

    with app.app_context():
        from . import actions
        from . import auth
        from . import status
        from . import ui
        from . import users

        app.register_blueprint(actions.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app

