from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    return response


if __name__ == '__main__':
    app.run()
