import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


# Create SQLAlchemy engine with connection pooling
engine = create_engine(f'sqlite:///{DB_FILENAME}', poolclass=QueuePool, pool_size=5, max_overflow=10)
Session = scoped_session(sessionmaker(bind=engine))

def query_db(query, args=(), one=False, commit=False):
    """
    Execute a raw SQL query using SQLAlchemy's connection pooling
    This function is kept for backward compatibility
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(query, args)
            if commit:
                conn.execution_options(isolation_level="AUTOCOMMIT")
            
            if one:
                return result.fetchone()
            else:
                return result.fetchall()
    except Exception as e:
        # Avoid exposing sensitive error information
        if commit:
            # If this was a write operation, log the error safely (without exposing data)
            print(f"Database error occurred: {type(e).__name__}")
        raise

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
