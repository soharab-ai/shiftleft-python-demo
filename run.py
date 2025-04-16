from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
def add_csp_headers(response, inline_scripts=None):
    # Dictionary to store hashes of allowed inline scripts
    script_hashes = []
    
    # If inline scripts are provided, calculate their SHA-256 hashes
    if inline_scripts:
        for script in inline_scripts:
            script_sha256 = hashlib.sha256(script.encode()).digest()
            b64_hash = base64.b64encode(script_sha256).decode()
            script_hashes.append(f"'sha256-{b64_hash}'")
    
    # Build the CSP header with hash-based validation instead of nonce
    csp_directives = [
        "default-src 'self'",
        f"script-src 'self' {' '.join(script_hashes)}", 
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "media-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'self'",
        "form-action 'self'",
        "require-trusted-types-for 'script'",  # Added Trusted Types Policy
        "report-uri https://your-reporting-endpoint.com/csp-reports",  # Added reporting capability
        "report-to default"  # Modern reporting directive
    ]
    
    # Set the Content-Security-Policy header
    response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
    
    # Set Permissions-Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    
    # Set Subresource Integrity expectations
    response.headers['Accept-CH'] = "Sec-CH-Subresource-Integrity"
    
    # CORS configuration with specific domain
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST'
    
    # Configure CSP reporting endpoint
    response.headers['Report-To'] = '{"group":"default","max_age":31536000,"endpoints":[{"url":"https://your-reporting-endpoint.com/csp-reports"}]}'
    
    return response

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
