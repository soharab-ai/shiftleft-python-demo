import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
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

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    with path.open("w", encoding="utf-8") as open_file:
        # vulnerability: Directory Traversal
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
# Dictionary of common processes that can be searched for - whitelist approach
ALLOWED_PROCESS_NAMES = {
    "chrome", "firefox", "safari", "edge", "python", "java", "nginx", 
    "apache2", "mysql", "postgres", "mongod", "node", "bash", "zsh",
    "systemd", "sshd", "httpd", "docker", "containerd", "cron"
}

# Rate limiting decorator
def rate_limit(max_calls=5, period=60):
    calls = null
    
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Clean up old entries
            calls_list = calls.get(client_ip, [])
            calls_list = [t for t in calls_list if current_time - t < period]
            
            if len(calls_list) >= max_calls:
                logging.warning(f"Rate limit exceeded for {client_ip} when accessing process list")
                return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
                
            calls_list.append(current_time)
            calls[client_ip] = calls_list
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

@rate_limit(max_calls=5, period=60)
def grep_processes():
    name = request.args.get("name")
    
    # Log the request for security monitoring
    logging.info(f"Process search requested for: {name}")
    
    # Whitelist validation instead of regex
    if name is None or name.lower() not in ALLOWED_PROCESS_NAMES:
        logging.warning(f"Invalid process name search attempted: {name}")
        return jsonify({"error": "Invalid process name. Only allowed process names can be searched."})
    
    # Use psutil library instead of subprocess - eliminates shell command entirely
    try:
        # Implement privilege separation by only collecting necessary data
        process_names = []
        for proc in psutil.process_iter(['name']):
            # More restrictive pattern matching with exact or word boundary checks
            proc_name = proc.info['name']
            if proc_name and name.lower() == proc_name.lower():
                process_names.append(proc_name)
        
        return jsonify({"success": True, "names": process_names})
    except Exception as e:
        logging.error(f"Error during process listing: {str(e)}")
        return jsonify({"error": "Failed to list processes"}), 500

def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
