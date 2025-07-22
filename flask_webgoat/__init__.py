import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # Fixed vulnerability: Implemented sanitized logging to prevent sensitive data exposure
        if os.environ.get('FLASK_ENV') == 'development':
            # Only enable logging in development environment
            def sanitize_query(query_string):
                # Define patterns for sensitive data
                patterns = [
                    (r'password\s*=\s*[\'"][^\'"]*[\'"]', 'password=*****'),
                    (r'card_number\s*=\s*[\'"][^\'"]*[\'"]', 'card_number=*****'),
                    (r'cvv\s*=\s*[\'"][^\'"]*[\'"]', 'cvv=*****'),
                    (r'ssn\s*=\s*[\'"][^\'"]*[\'"]', 'ssn=*****'),
                    (r'[0-9]{3}-[0-9]{2}-[0-9]{4}', '*****'),  # SSN pattern
                    (r'[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}', '*****-*****-*****-*****'),  # Credit card pattern
                ]
                
                # Apply sanitization
                sanitized = query_string
                for pattern, replacement in patterns:
                    sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
                
                return sanitized

            def safe_trace_callback(query):
                logging.debug(sanitize_query(query))
                
            # Configure proper logging
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                filename='app_debug.log'
            )
            
            conn.set_trace_callback(safe_trace_callback)
            
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
