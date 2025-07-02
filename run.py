from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
# Configuration section - ideally in a separate config file
def get_trusted_origins():
    # Fix: Move trusted origins to configuration rather than hardcoding
    return os.environ.get('TRUSTED_ORIGINS', 'https://trusted-site.com,https://other-trusted-site.com').split(',')

# Initialize Flask-CORS with default restrictive settings
def setup_cors(app):
    # Fix: Use Flask-CORS extension instead of custom implementation
    CORS(app, resources={
        # Fix: Implement route-specific CORS policies
        r"/api/*": {
            "origins": get_trusted_origins(),
            "supports_credentials": True,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"]
        },
        # More restrictive policy for sensitive routes
        r"/admin/*": {
            "origins": [os.environ.get('ADMIN_ORIGIN', 'https://admin.trusted-site.com')],
            "supports_credentials": True
        }
    })

# Enhanced security headers for all responses
def add_csp_headers(response):
    # Fix: Improve Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'"
    
    # Fix: Add SameSite cookie protection
    response.headers['Set-Cookie'] = response.headers.get('Set-Cookie', '') + '; SameSite=Strict; Secure; HttpOnly'
    
    # Fix: Add additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

# Register this function with Flask
def register_security_handlers(app):
    # Set up CORS with Flask-CORS
    setup_cors(app)
    
    # Apply security headers to all responses
    @app.after_request
    def process_response(response):
        return add_csp_headers(response)
    
    # Fix: Add explicit handling for OPTIONS preflight requests
    @app.before_request
    def handle_preflight():
        if request.method == 'OPTIONS':
            # Create a response for preflight requests
            response = Response()
            return add_csp_headers(response)
        
        # Fix: Add additional request validation for cross-origin requests
        if request.headers.get('Origin') and request.headers.get('Origin') not in get_trusted_origins():
            # Log suspicious cross-origin request attempts
            app.logger.warning(f"Suspicious cross-origin request from: {request.headers.get('Origin')}")
    
    return app

        # Fallback if config not available
        trusted_origins = ['https://trusted-domain.com']
        report_uri = '/csp-violation-report-endpoint/'
    
    # Specify trusted origins instead of using wildcard
    if len(trusted_origins) == 1:
        response.headers['Access-Control-Allow-Origin'] = trusted_origins[0]
    else:
        # If multiple origins, set based on request origin (would need request object)
        response.headers['Access-Control-Allow-Origin'] = trusted_origins[0]
        
    # Generate a random nonce for inline scripts (if needed)
    nonce = secrets.token_urlsafe(16)
    
    # Implement comprehensive CSP with nonce for necessary inline scripts
    csp_directives = {
        "default-src": "'self'",
        "script-src": f"'self' 'nonce-{nonce}'", 
        "style-src": "'self'",
        "img-src": "'self' https://trusted-cdn.com",
        "font-src": "'self'",
        "connect-src": "'self'",
        "media-src": "'self'",
        "object-src": "'none'",
        "frame-src": "'self'",
        "frame-ancestors": "'self'",
        "form-action": "'self'",
        "report-uri": report_uri,
        "upgrade-insecure-requests": ""
    }
    
    # Build the CSP header string
    csp_header = "; ".join([f"{key} {value}" for key, value in csp_directives.items() if value])
    
    # Set both enforcing CSP and report-only CSP for transition period
    response.headers['Content-Security-Policy'] = csp_header
    response.headers['Content-Security-Policy-Report-Only'] = csp_header
    
    # Store the nonce in the response object for template use
    response.csp_nonce = nonce
    
    return response


if __name__ == '__main__':
    app.run()
