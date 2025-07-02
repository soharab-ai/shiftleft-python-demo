from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Load CSP configuration from external file
    config = configparser.ConfigParser()
    try:
        config.read('csp_config.ini')
        trusted_origins = config['ORIGINS']['trusted_domains'].split(',')
        report_uri = config['REPORTING']['report_uri']
    except (KeyError, FileNotFoundError):
        # Fallback if config not available
        trusted_origins = ['https://trusted-domain.com']
        report_uri = '/csp-violation-report-endpoint/'
    
    # Specify trusted origins instead of using wildcard
    if len(trusted_origins) == 1:
        response.headers['Access-Control-Allow-Origin'] = trusted_origins[0]
    else:
        # If multiple origins, set based on request origin (would need request object)
        response.headers['Access-Control-Allow-Origin'] = trusted_origins[0]
        
    # Generate a random nonce for inline scripts (if needed)
    nonce = secrets.token_urlsafe(16)
    
    # Implement comprehensive CSP with nonce for necessary inline scripts
    csp_directives = {
        "default-src": "'self'",
        "script-src": f"'self' 'nonce-{nonce}'", 
        "style-src": "'self'",
        "img-src": "'self' https://trusted-cdn.com",
        "font-src": "'self'",
        "connect-src": "'self'",
        "media-src": "'self'",
        "object-src": "'none'",
        "frame-src": "'self'",
        "frame-ancestors": "'self'",
        "form-action": "'self'",
        "report-uri": report_uri,
        "upgrade-insecure-requests": ""
    }
    
    # Build the CSP header string
    csp_header = "; ".join([f"{key} {value}" for key, value in csp_directives.items() if value])
    
    # Set both enforcing CSP and report-only CSP for transition period
    response.headers['Content-Security-Policy'] = csp_header
    response.headers['Content-Security-Policy-Report-Only'] = csp_header
    
    # Store the nonce in the response object for template use
    response.csp_nonce = nonce
    
    return response


if __name__ == '__main__':
    app.run()
