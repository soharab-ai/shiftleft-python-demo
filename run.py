from flask_webgoat import create_app

app = create_app()

@app.after_request
def calculate_script_hash(script_content):
    # FIXED: Helper function to calculate SHA-256 hash for static inline scripts
    return 'sha256-' + hashlib.sha256(script_content.encode('utf-8')).hexdigest()

    nonce = secrets.token_urlsafe(16)
    
    # FIXED: Pre-calculated hashes for known static inline scripts (add actual script hashes here)
    # Example: known_script_hashes = [calculate_script_hash("console.log('static script');")]
    known_script_hashes = []  # Populate with actual static script hashes as needed
    
    # FIXED: Build hash string for CSP policy
    hash_directives = ' '.join([f"'{script_hash}'" for script_hash in known_script_hashes]) if known_script_hashes else ''
    
    # FIXED: Secure CSP configuration with nonce, hash support, and strict-dynamic
    csp_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' {hash_directives} 'strict-dynamic'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data: https:; "
        f"font-src 'self'; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"report-uri /csp-violation-report; "
        f"report-to csp-endpoint"
    ).strip()
    
    response.headers['Content-Security-Policy'] = csp_policy
    
    # FIXED: Whitelist-based CORS validation instead of hardcoded single domain
    ALLOWED_ORIGINS = [
        'https://trusted-domain.com',
        'https://subdomain.trusted-domain.com',
        'https://partner-domain.com'
    ]
    
    # FIXED: Validate origin against whitelist for flexible multi-origin support
    origin = getattr(request, 'headers', {}).get('Origin', '') if 'request' in globals() else ''
    if origin and origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        # Default to primary trusted domain
        response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
    
    # Store nonce for use in templates if needed
    response.nonce = nonce
    
    return response


if __name__ == '__main__':
    app.run()
