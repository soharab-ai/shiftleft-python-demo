from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
def add_csp_headers(response, nonce=None):
    # Generate a random nonce if none is provided
    if nonce is None:
        nonce = secrets.token_hex(16)
    
    # Comprehensive CSP implementation with multiple layers of protection
    csp_directives = [
        # Default fallback for unlisted directive types
        "default-src 'self'",
        
        # Script execution restrictions with nonce and strict-dynamic
        f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic'",
        
        # Style source restrictions
        "style-src 'self'",
        
        # Block plugins
        "object-src 'none'",
        
        # Control where images can be loaded from
        "img-src 'self' https://trusted-image-cdn.com",
        
        # Control where forms can submit to
        "form-action 'self'",
        
        # Control valid sources for embedded content
        "frame-src 'self'",
        
        # Control valid sources for web workers and nested browsing contexts
        "worker-src 'self'",
        
        # Control which URLs can be loaded using fetch, XHR, etc.
        "connect-src 'self' https://api.trusted-domain.com",
        
        # Configure reporting for CSP violations
        "report-uri /csp-violation-report-endpoint/",
        
        # Upgrade-Insecure-Requests ensures HTTPS is used when possible
        "upgrade-insecure-requests"
    ]
    
    # Apply the CSP directives
    response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
    
    # Also set a report-only version to help with transition and debugging
    response.headers['Content-Security-Policy-Report-Only'] = "; ".join(csp_directives + 
        ["report-uri /csp-report-only-endpoint/"])
    
    # Replace overly permissive CORS policy with specific trusted domain
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
    
    # Add X-Content-Type-Options to prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Add X-Frame-Options to prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Add X-XSS-Protection as an additional layer of XSS protection for older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Return both the modified response and the generated nonce
    # so it can be used in script tags as: <script nonce="generated-nonce-value">
    return response, nonce

    app.run()
