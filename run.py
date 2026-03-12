from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # FIX: Enhanced origin validation using regex patterns instead of simple string matching
    # to prevent subdomain attacks, protocol confusion, and port-based bypasses
    ALLOWED_PATTERNS = [
        re.compile(pattern.strip()) 
        for pattern in os.getenv('ALLOWED_ORIGINS', '^https:\/\/(www\.)?yourdomain\.com$').split(',')
    ]
    
    # Get the origin from the incoming request
    origin = request.headers.get('Origin')
    
    # FIX: Validate origin against regex patterns with strict matching
    origin_validated = False
    if origin:
        for pattern in ALLOWED_PATTERNS:
            if pattern.match(origin):
                response.headers['Access-Control-Allow-Origin'] = origin
                # FIX: Add Vary header to prevent caching issues where proxies/CDNs serve 
                # the same CORS response to different origins
                response.headers['Vary'] = 'Origin'
                origin_validated = True
                break  # Exit after first match
        
        # FIX: Add logging for security monitoring of rejected origins
        if not origin_validated:
            # Sanitize origin before logging to prevent log forging/injection
            sanitized_origin = origin.replace('\n', '').replace('\r', '')[:200]
            logging.warning(f"CORS request rejected from unauthorized origin: {sanitized_origin}")
    
    # FIX: Only allow credentials with validated origins to prevent session hijacking
    if origin_validated:
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # FIX: Handle CORS preflight (OPTIONS) requests explicitly to support complex cross-origin requests
    if request.method == 'OPTIONS' and origin_validated:
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Max-Age'] = '3600'
    
    # FIX: Removed 'unsafe-inline' from CSP to prevent inline script injection attacks
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    
    # FIX: Added additional security headers for defense-in-depth
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response


if __name__ == '__main__':
    app.run()
