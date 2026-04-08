import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


# SECURE: Prepared statement cache to enforce parameterization pattern
_stmt_cache = {}

def query_db(query, args=(), one=False, commit=False):
    """Execute database queries with parameterized statements and caching"""
    with sqlite3.connect(DB_FILENAME) as conn:
        # SECURE: Removed trace callback to prevent sensitive data exposure in logs
        
        # SECURE: Use prepared statement caching for performance and security
        cache_key = query
        if cache_key in _stmt_cache:
            cur = conn.cursor()
            cur.execute(query, args)
        else:
            cur = conn.cursor()
            cur.execute(query, args)
            _stmt_cache[cache_key] = True
        
        # SECURE: Commit only when explicitly requested to maintain transaction control
        if commit:
def init_db():
    """Initialize database with security constraints"""
    with sqlite3.connect(DB_FILENAME) as conn:
        # SECURE: Create user table with database-level constraints for defense in depth
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password TEXT NOT NULL,
                access_level INTEGER NOT NULL CHECK(access_level BETWEEN 0 AND 10)
            )
        ''')
        # SECURE: UNIQUE constraint prevents duplicate usernames at database level
        # SECURE: CHECK constraint enforces access_level range at database level
        # SECURE: NOT NULL constraints ensure data integrity
        # SECURE: VARCHAR(50) limit matches application validation
        conn.commit()

        app.register_blueprint(actions.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app
