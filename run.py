from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Removed broken access control by not setting the wildcard
    # Removed security misconfiguration by not allowing inline scripts
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    return response



if __name__ == '__main__':
    app.run()


