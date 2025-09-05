from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Fixed: Replace hardcoded trusted origins with configuration-based approach
    trusted_origins = app.config.get('TRUSTED_ORIGINS', '').split(',')
    
    # Get the origin from the request
    origin = request.headers.get('Origin')
    
    # Fixed: Implement subdomain validation with pattern matching
    if origin and is_trusted_origin(origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        # Fixed: Add CORS preflight response handling
        if request.method == 'OPTIONS':
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Max-Age'] = '3600'
    elif origin:
        # Fixed: Log CORS violations for monitoring
        app.logger.warning(f"Rejected CORS request from untrusted origin: {origin}")
    
    # Fixed: Improved Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    
    return response

# Helper function to validate origins including subdomain patterns
def is_trusted_origin(origin):
    trusted_origins = app.config.get('TRUSTED_ORIGINS', '').split(',')
    for trusted in trusted_origins:
        if trusted.startswith('*.') and origin.endswith(trusted[1:]):
            return True
    return origin in trusted_origins

# Fixed: Use specialized Flask-CORS middleware for more robust handling
def configure_cors(app):
    trusted_origins = app.config.get('TRUSTED_ORIGINS', '').split(',')
    CORS(app, resources={r"/api/*": {"origins": trusted_origins, "supports_credentials": True}})

if __name__ == '__main__':
    app.run()
