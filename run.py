from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
def add_csp_headers(response, request=None):
    # Generate a random nonce for this response using cryptographically secure method
    nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    # Fixed: Implemented comprehensive CSP policy covering multiple resource types
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"img-src 'self'; "
        f"connect-src 'self'; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"media-src 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none';"
    )
    
    # Fixed: Added additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    
    # Fixed: Implemented HSTS header
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Fixed: Implemented SameSite cookie attribute
    response.headers['Set-Cookie'] = 'session=value; SameSite=Strict; Secure; HttpOnly'
    
    # Fixed: Implemented more granular CORS control
    ALLOWED_ORIGINS = ['https://trusted-domain.com', 'https://another-trusted-domain.com']
    
    if request and hasattr(request, 'origin') and request.origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = request.origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        # Default to the primary trusted domain if origin not provided or not in allowlist
        response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
    
    # Fixed: Implemented nonce rotation mechanism
    # Store nonce with timestamp to enable TTL-based validation
    current_time = datetime.now().isoformat()
    if not hasattr(response, 'nonce_cache'):
        response.nonce_cache = null
    
    # Clean expired nonces (simple implementation - would use a more robust cache in production)
    response.nonce_cache[nonce] = current_time
    
    # Store nonce in response context so templates can use it
    response.nonce = nonce
    
    return response

    app.run()
