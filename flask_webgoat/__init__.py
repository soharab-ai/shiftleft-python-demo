import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def validate_query_pattern(query):
    """Validate query against whitelist of allowed patterns to prevent unauthorized SQL commands"""
    # FIX: Implement query pattern whitelisting for additional SQL injection defense layer
    ALLOWED_QUERY_PATTERNS = [
        r'^SELECT .+ FROM user WHERE .+',
        r'^INSERT INTO user \(username, password, access_level\) VALUES \(\?, \?, \?\)$',
        r'^UPDATE user SET .+ WHERE .+',
        r'^DELETE FROM user WHERE .+',
        r'^SELECT .+ FROM user$'
    ]
    
    if not any(re.match(pattern, query.strip(), re.IGNORECASE) for pattern in ALLOWED_QUERY_PATTERNS):
        raise ValueError("Unauthorized query pattern detected")
    return True

    if db_path.exists():
def query_db(query, args=(), one=False, commit=False):
    # FIX: Add query length and complexity limits to prevent resource exhaustion attacks
    MAX_QUERY_LENGTH = 500
    MAX_PLACEHOLDERS = 10
    
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError("Query exceeds maximum allowed length")
    if query.count('?') > MAX_PLACEHOLDERS:
        raise ValueError("Query exceeds maximum allowed parameters")
    
    # FIX: Validate query pattern against whitelist before execution
    validate_query_pattern(query)
    
    # FIX: Implement security-focused query monitoring with sanitization
    security_logger = logging.getLogger('security.database')
    sanitized_query = re.sub(r'\b\d+\b', '[NUM]', query)
    sanitized_query = re.sub(r"'[^']*'", '[STR]', sanitized_query)
    security_logger.info(f"DB Query Pattern: {sanitized_query}, Param Count: {len(args)}")
    
    with sqlite3.connect(DB_FILENAME) as conn:
        # FIX: Enforce read-only mode for non-commit queries to prevent privilege escalation
        if not commit:
            conn.execute("PRAGMA query_only = ON")
        
        # FIX: Remove trace callback to prevent sensitive data exposure in logs
        # FIX: Use prepared statement approach with explicit cursor for better security
        cur = conn.cursor()
        cur.execute(query, args)
        
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()
