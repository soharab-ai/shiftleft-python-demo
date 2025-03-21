import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
def log_entry():
    # Define maximum allowed log size (5MB)
    MAX_LOG_SIZE = 5 * 1024 * 1024
    
    try:
        user_info = session.get("user_info", None)
        if user_info is None:
            return jsonify({"error": "no user_info found in session"})
        
        access_level = user_info[2]
        if access_level > 2:
            return jsonify({"error": "access level < 2 is required for this action"})
        
        filename_param = request.form.get("filename")
        if filename_param is None:
            return jsonify({"error": "filename parameter is required"})
        
        text_param = request.form.get("text")
        if text_param is None:
            return jsonify({"error": "text parameter is required"})
        
        # Add size limitation to prevent DoS attacks
        if len(text_param) > MAX_LOG_SIZE:
            return jsonify({"error": "Text exceeds maximum allowed size"})
        
        # Implement whitelist validation for filename characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', filename_param):
            return jsonify({"error": "Filename contains invalid characters"})
        
# Dictionary to keep track of API calls for rate limiting
request_history = null

# Rate limiting decorator
def rate_limit(max_calls=5, time_window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Initialize or clean up old entries
            if client_ip not in request_history:
                request_history[client_ip] = []
            request_history[client_ip] = [t for t in request_history[client_ip] if current_time - t < time_window]
            
            # Check if rate limit exceeded
            if len(request_history[client_ip]) >= max_calls:
                current_app.logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
                
            # Add timestamp and process request
            request_history[client_ip].append(current_time)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@bp.route("/grep_processes")
@rate_limit(max_calls=5, time_window=60)  # Added rate limiting
def grep_processes():
    name = request.args.get("name", "")
    
    # Input validation with whitelist approach instead of blacklist
    allowed_search_terms = ["python", "nginx", "apache", "mysql", "postgres", "java", "node"]
    if name and name not in allowed_search_terms:
        # Log security event
        current_app.logger.warning(f"Invalid process name search attempt: {name} from IP: {request.remote_addr}")
        return jsonify({"error": "Invalid search term. Please use one of the allowed terms."})
    
    try:
        # Using psutil instead of subprocess for more secure and platform-independent operation
        process_names = []
        for proc in psutil.process_iter(['name']):
            try:
                process_info = proc.info
                if name in process_info['name']:
                    process_names.append(process_info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle errors gracefully and continue with next process
                pass
                
        return jsonify({"success": True, "names": process_names})
        
    except Exception as e:
        # Log the error but don't expose details to the client
        current_app.logger.error(f"Error in process listing: {str(e)}")
        return jsonify({"error": "An error occurred while listing processes"}), 500

        
        # Ensure the path doesn't go outside the intended directory
        final_path = os.path.abspath(path)
        if not final_path.startswith(user_dir):
            return jsonify({"error": "Invalid path detected"})
        
        # Sanitize log content to prevent log injection
        sanitized_text = html.escape(text_param)
        
        try:
            with open(final_path, "w", encoding="utf-8") as open_file:
                # Write sanitized content to prevent log injection/forging
                open_file.write(sanitized_text)
            return jsonify({"success": True})
        except IOError as e:
            logging.error(f"Error writing to log file: {e}")
            return jsonify({"error": "Failed to write log entry"})
            
    except Exception as e:
        # Comprehensive error handling
        logging.error(f"Unexpected error in log_entry: {str(e)}")
        return jsonify({"error": "An internal error occurred"})

def grep_processes():
    name = request.args.get("name")
    # vulnerability: Remote Code Execution
    res = subprocess.run(
        ["ps aux | grep " + name + " | awk '{print $11}'"],
        shell=True,
        capture_output=True,
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    out = res.stdout.decode("utf-8")
    names = out.split("\n")
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
