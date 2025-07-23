import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # Removed sensitive data exposure vulnerability
        # Only log in development environment with sanitized queries
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            # Sanitize the query before logging to avoid exposing sensitive data
            sanitized_query = re.sub(r'(password|token|secret|credential|key)\s*=\s*[^\s,)]*', r'\1=********', query)
            logging.debug("Executing query: %s", sanitized_query)
            # Don't log arguments as they may contain sensitive data
            
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
