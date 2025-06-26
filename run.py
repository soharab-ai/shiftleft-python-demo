from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Load CSP configuration from central config
    csp_config = current_app.config.get('CSP_CONFIG', null)
    report_uri = csp_config.get('report_uri', '/csp-violation-report-endpoint')
    trusted_origins = csp_config.get('trusted_origins', ['https://trusted-origin.com'])
    
    # Fixed: Restrict CORS to specific origins instead of allowing all
    if trusted_origins and len(trusted_origins) == 1:
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
