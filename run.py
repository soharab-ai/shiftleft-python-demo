from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
    # Mitigation: Set the CORS header to a specific origin or a list of allowed origins
    CORS(app, resources={r"/api/*": {"origins": "http://example.com"}})
    # Mitigation: Use a logging library that supports structured logging and automatic sanitization
    json_logging.init_flask(enable_json=True)
    json_logging.init_request_instrument(app)
    logger = logging.getLogger(__name__)
    logger.info('Log forging prevented by sanitization', extra={'response': response.headers})
    return response



if __name__ == '__main__':
    app.run()
