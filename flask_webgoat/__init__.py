import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"
def get_db():
    # FIXED: Initialize SQLAlchemy database instance for ORM-based queries
    return db
# FIXED: Added SQLAlchemy ORM model to replace raw SQL queries
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    access_level = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    if placeholder_count > 0 and len(args) == 0:
        raise ValueError("Query has placeholders but no arguments provided")
    
    if len(args) > 0 and placeholder_count == 0:
        raise ValueError("Arguments provided but query has no placeholders")
    
    if placeholder_count != len(args):
        raise ValueError(f"Mismatch between placeholders ({placeholder_count}) and arguments ({len(args)})")
    
    # FIXED: Enhanced whitelist validation using SQL parser to detect dangerous patterns
    dangerous_patterns = [
        r';\s*DROP',
        r';\s*DELETE\s+FROM\s+\w+\s*;',
        r';\s*UPDATE.*--',
        r'UNION\s+ALL\s+SELECT',
        r'UNION\s+SELECT',
        r'--\s*$',
        r'/\*',
        r'\*/',
        r';\s*INSERT',
        r';\s*ALTER',
        r';\s*CREATE',
        r'xp_cmdshell',
        r';\s*EXEC',
        r';\s*EXECUTE',
        r'0x[0-9a-fA-F]+',  # Hex encoding attempts
        r'CHAR\s*\(',        # CHAR-based encoding
        r'CONCAT\s*\(',      # Concatenation attacks
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            raise ValueError("Potentially dangerous SQL pattern detected")
    
    with sqlite3.connect(DB_FILENAME) as conn:
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
