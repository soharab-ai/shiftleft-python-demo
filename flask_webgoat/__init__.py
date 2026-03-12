import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def sanitize_query(query):
    """Sanitize SQL queries using proper SQL parsing"""
    # FIX: Using sqlparse library for robust SQL parsing instead of regex
    try:
        parsed = sqlparse.parse(query)
        if not parsed:
            return "***QUERY_PARSING_ERROR***"
        
        statement = parsed[0]
        tokens = []
        for token in statement.flatten():
            # FIX: Mask all literal values (strings, numbers) using SQL token analysis
            if token.ttype in (sqlparse.tokens.String, sqlparse.tokens.String.Single, 
                              sqlparse.tokens.String.Symbol, sqlparse.tokens.Number.Integer,
                              sqlparse.tokens.Number.Float, sqlparse.tokens.Number.Hexadecimal):
                tokens.append(sqlparse.sql.Token(token.ttype, '***REDACTED***'))
            else:
                tokens.append(token)
        
        return ''.join(str(t) for t in tokens)
    except Exception:
        # FIX: Handle parsing errors gracefully
def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # FIX: Removed conn.set_trace_callback(print) to prevent sensitive data exposure
        # FIX: Implement conditional sanitized logging only in development mode
        if os.getenv('DEBUG_MODE') == 'true' and os.getenv('ENABLE_QUERY_LOGGING') == 'true':
            # FIX: Use proper logging with sanitization for both query and args
            sanitized_query = sanitize_query(query)
            # FIX: Mask the args parameter values to prevent exposure of sensitive data in parameterized queries
            sanitized_args = tuple('***REDACTED***' for _ in args) if args else ()
            logging.info(f"Executing sanitized query: {sanitized_query} with args: {sanitized_args}")
        elif os.getenv('ENABLE_QUERY_LOGGING') == 'true':
            # FIX: In production, log only query execution event without details
            logging.info("Database query executed")
        
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()

        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app
