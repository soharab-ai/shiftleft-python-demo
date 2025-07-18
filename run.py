from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
def add_csp_headers(response, request=None, critical_script=None):
    # Fixed: Restricting CORS to specific trusted origin instead of wildcard
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-site.com'
    
    # Fixed: Removed 'unsafe-inline' directive and implemented nonce-based CSP
    nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    # Added: Hash-based CSP as fallback for critical inline scripts
    csp_directives = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'"
    
    # Add hash-based validation for critical scripts if provided
    if critical_script:
        script_hash = base64.b64encode(hashlib.sha256(critical_script.encode()).digest()).decode('utf-8')
        csp_directives += f" 'sha256-{script_hash}'"
    
    # Complete the CSP directives
    csp_directives += "; object-src 'none'; img-src 'self'; style-src 'self'"
    
    # Added: CSP reporting mechanism
    csp_directives += "; report-uri /csp-violation-report-endpoint"
    
    # Set the complete CSP header
    response.headers['Content-Security-Policy'] = csp_directives
    
    # Added: Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Add the nonce to the response so templates can use it
    response.nonce = nonce
    
    # Added: Store nonce in session for validation if request object available
    if request and hasattr(request, 'session'):
        request.session['csp_nonce'] = nonce
    
    return response

    app.run()
