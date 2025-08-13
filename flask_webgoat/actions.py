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

# Sanitize the filename to prevent path traversal
safe_filename = sanitize_filename(filename_param) + ".txt"

# Create the path securely using path joining
path = user_dir_path / safe_filename

# Validate that the resolved path is within the user directory to prevent directory traversal
if not os.path.normpath(os.path.realpath(str(path))).startswith(os.path.normpath(os.path.realpath(str(user_dir_path)))):
@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    redirect_url = request.args.get("redirect_url", "/")
    
    # Input validation - only allow alphanumeric characters and common symbols
    import re
    if name is None or not re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
        return jsonify({"error": "Invalid input"})
    
    # URL redirect validation - only allow safe URLs
    from urllib.parse import urlparse
    def is_safe_redirect_url(url):
        # Whitelist of allowed domains or validate relative URLs
        allowed_domains = ['trusted-domain.com', 'example.com']
        parsed = urlparse(url)
@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    MAX_PAYLOAD_SIZE = 10240  # Limit payload to 10KB
    pickled = request.form.get('pickled')
    try:
        data = base64.urlsafe_b64decode(pickled)
        
        # Prevent DoS attacks with large payloads
        if len(data) > MAX_PAYLOAD_SIZE:
            return jsonify({"success": False, "error": "Payload too large"}), 413
        
        # Validate that the content is actually JSON before processing
        json_data = data.decode('utf-8')
        # Using JSON instead of pickle for safe deserialization
        deserialized = json.loads(json_data)
        
        # Implement basic schema validation
        if not isinstance(deserialized, dict):
            return jsonify({"success": False, "error": "Invalid data structure"}), 400
        
        # Log successful deserialization
        current_app.logger.info("Successful data deserialization")
        return jsonify({"success": True, "description": str(deserialized)})
    except json.JSONDecodeError:
        current_app.logger.warning("Invalid JSON format in deserialization attempt")
        return jsonify({"success": False, "error": "Invalid JSON format"}), 400
    except Exception as e:
        current_app.logger.warning(f"Deserialization attempt failed: {type(e).__name__}")
        return jsonify({"success": False, "error": "Invalid data format"}), 400

    # Execute commands safely without shell=True
    ps_process = subprocess.run(
        ["ps", "aux"],
        capture_output=True,
        text=True
    )
    
    grep_process = subprocess.run(
        ["grep", name],
        input=ps_process.stdout,
        capture_output=True,
        text=True
    )
    
    awk_process = subprocess.run(
        ["awk", "{print $11}"],
        input=grep_process.stdout,
        capture_output=True,
        text=True
    )
    
    if not awk_process.stdout:
        return jsonify({"error": "no stdout returned"})
    
    # Return result with safe redirect URL
    return jsonify({"result": awk_process.stdout.strip(), "redirect_url": redirect_url})

    name = request.args.get("name")
    
    # Validate input
    import re
    if name is None or not re.match(r'^[a-zA-Z0-9_\-. ]+$', name):
        return jsonify({"error": "Invalid input"})
    
    # Use psutil instead of subprocess for process monitoring
    import psutil
    
    try:
        filtered_processes = []
        for proc in psutil.process_iter(['name', 'cmdline']):
            process_info = proc.info
            process_cmd = " ".join(process_info['cmdline']) if process_info['cmdline'] else ""
            if name in process_cmd or (process_info['name'] and name in process_info['name']):
                filtered_processes.append(process_cmd if process_cmd else process_info['name'])
        
        return jsonify({"processes": filtered_processes})
    except Exception as e:
        return jsonify({"error": str(e)})

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
