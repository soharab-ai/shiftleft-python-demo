from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
def is_trusted_origin(origin):
    # Added: Function to check if origin is trusted, including subdomain support
    if not origin:
        return False
    trusted_origins = os.environ.get('TRUSTED_ORIGINS', 'https://trusted-site.com,https://another-trusted-site.com').split(',')
    for trusted in trusted_origins:
        if origin == trusted or (trusted.startswith('*.') and origin.endswith(trusted[1:])):
            return True
    return False

def add_csp_headers(response):
    # Modified: Using environment variables for trusted origins
    origin = request.headers.get('Origin')
    
    if is_trusted_origin(origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        # Added: Vary header to prevent caching issues
        response.headers['Vary'] = 'Origin'
    else:
        if origin:  # Added: Logging for rejected CORS requests
            app.logger.warning(f"Rejected CORS request from untrusted origin: {origin}")
    
    # Improved CSP header
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    return response

# CORS preflight handling with rate limiting
def setup_cors_and_security(app):
    # Added: Using Flask-CORS for robust CORS handling
    trusted_origins = os.environ.get('TRUSTED_ORIGINS', 'https://trusted-site.com,https://another-trusted-site.com').split(',')
    cors = CORS(app, resources={r"/api/*": {"origins": trusted_origins, "supports_credentials": True}})
    
    # Added: Rate limiting for CORS requests
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    
    @app.route('/api/<path:path>', methods=['OPTIONS'])
    @limiter.limit("100 per hour")  # Added: Rate limiting for preflight requests
    def cors_preflight(path):
        response = make_response()
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Max-Age'] = '3600'
        # Apply the same origin restrictions
        return add_csp_headers(response)
    
    # Added: Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    @app.after_request
    def apply_csp_headers(response):
        return add_csp_headers(response)
        
    return app

        response.headers['Access-Control-Allow-Origin'] = trusted_origins[0]
    else:
        # If multiple origins are configured, this would need to be handled dynamically
        # based on the Origin header of the request
        response.headers['Access-Control-Allow-Origin'] = 'https://trusted-origin.com'
    
    # Fixed: Removed 'unsafe-inline' and implemented nonce-based CSP
    nonce = secrets.token_urlsafe(16)
    
    # Added: Calculate hash for any static inline scripts if needed
    # Example hash computation for a static script
    static_script = "console.log('This is a static script');"
    script_hash = 'sha256-' + hashlib.sha256(static_script.encode()).hexdigest()
    
    # Added: Comprehensive CSP with all suggested improvements
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'sha256-{script_hash}' 'strict-dynamic'; "
        f"object-src 'none'; "
        f"frame-ancestors 'none'; "
        f"report-uri {report_uri}; "
        f"upgrade-insecure-requests; "
    )
    
    # Added: Additional security headers for defense-in-depth
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Make the nonce available for templates
    response.nonce = nonce
    return response


if __name__ == '__main__':
    app.run()
