from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Removing the Access-Control-Allow-Origin header
    # response.headers['Access-Control-Allow-Origin'] = '*'
    # Removing the unsafe-inline directive from Content-Security-Policy
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    return response


if __name__ == '__main__':
    app.run()

