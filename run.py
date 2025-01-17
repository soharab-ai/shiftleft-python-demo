from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Content-Security-Policy'] = "script-src 'self'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'; report-uri /csp-violation-report-endpoint/"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


if __name__ == '__main__':
    app.run()
