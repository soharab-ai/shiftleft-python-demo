import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    # FIXED: Added query pattern whitelist validation for defense-in-depth
    allowed_patterns = [
        r'^SELECT .+ FROM user WHERE username = \?$',
        r'^SELECT .+ FROM user WHERE username = \? AND .+$',
        r'^INSERT INTO .+ VALUES \(.+\)$',
        r'^UPDATE .+ SET .+ WHERE .+$'
    ]
    
    if not any(re.match(pattern, query.strip()) for pattern in allowed_patterns):
        raise ValueError("Query pattern not in whitelist")
    
    # FIXED: Added comprehensive error handling with sanitized logging
    try:
        with sqlite3.connect(DB_FILENAME) as conn:
            # FIXED: Removed conn.set_trace_callback(print) to prevent SQL queries from being logged
            cur = conn.cursor().execute(query, args)
            if commit:
                conn.commit()
            return cur.fetchone() if one else cur.fetchall()
    except sqlite3.Error as e:
        # FIXED: Log error without exposing sensitive query details, preventing log injection
        logger = logging.getLogger(__name__)
        # Sanitize error message by removing newline characters and limiting length
        sanitized_error = str(e).replace('\n', '').replace('\r', '')[:200]
        logger.error(f"Database error occurred: {sanitized_error}")
        return None

