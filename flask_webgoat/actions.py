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
        
        user_id = user_info[0]
        user_dir = os.path.abspath(f"data/{str(user_id)}")
        
        # Fix race condition by using exist_ok parameter
        try:
            os.makedirs(user_dir, exist_ok=True)
        except OSError:
            logging.error(f"Failed to create directory: {user_dir}")
            return jsonify({"error": "Could not create user directory"})
        
        # Sanitize the filename by using os.path.basename to strip any path components
        filename = os.path.basename(filename_param) + ".txt"
        
        # Use os.path.join for secure path construction
        path = os.path.join(user_dir, filename)
        
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
