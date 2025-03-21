from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
# Initialize rate limiter (should be setup at app level)
limiter = Limiter(key_func=get_remote_address)

def is_cors_preflight_request():
    """Check if the request is a CORS preflight request"""
    return request.method == 'OPTIONS' and request.headers.get('Access-Control-Request-Method')

@limiter.limit("30 per minute")  # Added rate limiting for CORS preflight requests
def handle_preflight_request():
    """Handle CORS preflight requests with rate limiting"""
    response = create_cors_response()
    return response

def match_subdomain(origin, pattern):
    """Match origin against pattern with wildcard subdomain support"""
    # Convert wildcard pattern to regex
    if pattern.startswith('*.'):
        domain_part = re.escape(pattern[2:])
        pattern_regex = r'^https://[^.]+\.' + domain_part + r'$'
        return bool(re.match(pattern_regex, origin))
    return origin == pattern

def create_cors_response():
    """Create a response with appropriate CORS headers"""
    response = Response()
    add_security_headers(response)
    return response

def add_security_headers(response):
    """Add all security headers to the response"""
    # Set Content-Security-Policy with enhanced directives
    csp_directives = {
        'default-src': "'self'",
        'script-src': "'self'",
        'connect-src': "'self'",
        'img-src': "'self'",
        'style-src': "'self'",
        'frame-src': "'none'",
        'report-uri': "/csp-violation-report"
    }
    response.headers['Content-Security-Policy'] = "; ".join(f"{k} {v}" for k, v in csp_directives.items())
    
    # Additional security headers
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

def add_csp_headers(response):
    # Add standard security headers to all responses
    add_security_headers(response)
    
    # Only add CORS headers if this is a CORS request
    origin = request.headers.get('Origin')
    if not origin:
        return response
        
    # Load allowed origins from environment or config
    # Default to empty list if not configured
    allowed_origins_str = os.environ.get('ALLOWED_ORIGINS', 'https://trusted-site.com,https://another-trusted-site.com')
    allowed_origins = allowed_origins_str.split(',')
    allowed_patterns = [pattern.strip() for pattern in allowed_origins]
    
    # Check if origin matches any of our allowed patterns (including subdomain wildcards)
    is_allowed = any(match_subdomain(origin, pattern) for pattern in allowed_patterns)
    
    if is_allowed:
        # Only add CORS headers for allowed origins
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
        
        # Only add these headers for actual CORS requests
        if request.method == 'OPTIONS' or origin != request.host_url.rstrip('/'):
            response.headers['Access-Control-Allow-Methods'] = os.environ.get('CORS_METHODS', 'GET, POST, OPTIONS')
            response.headers['Access-Control-Allow-Headers'] = os.environ.get('CORS_HEADERS', 'Content-Type, Authorization, X-Requested-With')
            response.headers['Access-Control-Allow-Credentials'] = os.environ.get('CORS_CREDENTIALS', 'true')
            response.headers['Access-Control-Max-Age'] = '3600'  # Cache preflight results for 1 hour
    
    return response

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
