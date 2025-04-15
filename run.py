from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Fix: Load trusted origins from app config instead of hardcoding
    trusted_origins = current_app.config.get('CORS_TRUSTED_ORIGINS', 
                                            ['https://trusted-site.com', 'https://another-trusted-site.com'])
    origin = request.headers.get('Origin')
    
    # Fix: Add security monitoring for rejected CORS requests
    if origin and origin not in trusted_origins:
        current_app.logger.warning(f"Rejected CORS request from untrusted origin: {origin}")
        
    # Fix: Only set CORS headers for trusted origins
    if origin in trusted_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        # Fix: Add support for authenticated CORS requests
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        # Fix: Handle OPTIONS preflight requests
        if request.method == 'OPTIONS':
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Max-Age'] = '3600'  # Cache preflight for 1 hour
    
    # Improved Content-Security-Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response


if __name__ == '__main__':
    app.run()
