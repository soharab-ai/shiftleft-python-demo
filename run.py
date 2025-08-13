from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Generate a secure random nonce for CSP
    nonce = secrets.token_hex(16)
    
    # Store nonce in session for consistency across requests
    session['csp_nonce'] = nonce
    
    # Implement comprehensive CSP with multiple directives and strict-dynamic
    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; "
        f"script-src 'strict-dynamic' 'nonce-{nonce}' 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self'; "
        f"connect-src 'self'; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"frame-ancestors 'none'; "
        f"form-action 'self'; "
        f"base-uri 'self'; "
        f"upgrade-insecure-requests; "
        f"report-uri /csp-violation-report-endpoint"
    )
    
    # Add additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    
    # Restrict cross-origin access to specific trusted origin
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-origin.com'
    
    return response, nonce


if __name__ == '__main__':
    app.run()
