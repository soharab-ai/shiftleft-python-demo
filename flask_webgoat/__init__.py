import os
import sqlite3
from pathlib import Path

from flask import Flask, g
import logging
import hashlib
import time

DB_FILENAME = "database.db"

# SECURITY FIX: Configure logging with production-safe defaults
log_level = logging.WARNING if os.getenv('FLASK_ENV') == 'production' else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # SECURITY FIX: Explicitly disable trace callbacks to prevent sensitive data exposure
        conn.set_trace_callback(None)
        
        # SECURITY FIX: Log only execution metadata, never query content or parameters
        query_hash = hashlib.md5(query.encode()).hexdigest()[:8]
        start_time = time.time()
        
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        
        # SECURITY FIX: Log metadata only for operational insights without exposing sensitive data
        execution_time = time.time() - start_time
        logger.info("Query executed", extra={
            'query_fingerprint': query_hash,
            'execution_time_ms': round(execution_time * 1000, 2),
            'rows_affected': cur.rowcount,
            'committed': commit
        })
        
        return cur.fetchone() if one else cur.fetchall()

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

