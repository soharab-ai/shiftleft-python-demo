import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # Fixed vulnerability: Sensitive Data Exposure using dedicated security logging
        # Only enable logging in development environment with proper sanitization
        if os.environ.get("ENVIRONMENT") == "development":
            # Load sanitization rules from configuration
            config_path = current_app.config.get('LOG_SANITIZATION_CONFIG', 'log_sanitization_rules.yaml')
            
            try:
                with open(config_path) as f:
                    sanitization_rules = yaml.safe_load(f)
            except (FileNotFoundError, yaml.YAMLError):
                # Fallback to default rules if config file unavailable
                sanitization_rules = {
                    'patterns': [
                        {'regex': r'password\s*=\s*[\'"][^\'"]*[\'"]', 'replacement': 'password=\'********\''},
                        {'regex': r'credit_card\s*=\s*[\'"][^\'"]*[\'"]', 'replacement': 'credit_card=\'********\''},
                        {'regex': r'ssn\s*=\s*[\'"][^\'"]*[\'"]', 'replacement': 'ssn=\'********\''},
                        {'regex': r'api_key\s*=\s*[\'"][^\'"]*[\'"]', 'replacement': 'api_key=\'********\''},
                    ]
                }
            
            # Set up structured logging with explicit field marking and sanitization
            structlog.configure(
                processors=[
                    structlog.processors.add_log_level,
                    structlog.processors.TimeStamper(fmt="iso"),
                    JSONRenderer(),
                ],
                logger_factory=structlog.stdlib.LoggerFactory(),
            )
            
            structured_logger = structlog.get_logger()
            
            def secure_logger(query):
                # Implement sanitization directly without using invalid library
                sanitized_query = query
                for pattern in sanitization_rules['patterns']:
                    sanitized_query = re.sub(
                        pattern['regex'],
                        pattern['replacement'],
                        sanitized_query
                    )
                
                # Use structured logging with explicit sensitive field marking
                structured_logger.debug(
                    "database_query",
                    sanitized_query=sanitized_query,
                    query_type="sql",
                    sensitive_data_handled=True
                )
            
            # Only add trace callback in development with proper sanitization
            conn.set_trace_callback(secure_logger)
            
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()



def create_app():
    app = Flask(__name__)
    app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"

    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    conn.execute(create_table_query)

    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', 'maximumentropy', 0)"""
    conn.execute(insert_admin_query)
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
