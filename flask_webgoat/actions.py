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
def grep_processes():
    name = request.args.get("name")
    
    # Fix 1: Implement allowlisting instead of blocklisting approach
    ALLOWED_PROCESS_NAMES = ["apache2", "nginx", "mysql", "python", "firefox", "chrome", "systemd"]
    if name not in ALLOWED_PROCESS_NAMES:
        # Fix 4: Add security logging for potential abuse attempts
        current_app.logger.warning(f"Unauthorized process lookup attempt: {shlex.quote(name)} by user: {session.get('user_id', 'unknown')}")
        return jsonify({"error": "Unauthorized process name"})
    
    # Fix 2: Use shlex for proper command sanitization
    sanitized_name = shlex.quote(name)
    
    # Fix 4: Log legitimate process lookup attempts
    current_app.logger.info(f"Process lookup requested for: {sanitized_name} by user: {session.get('user_id', 'unknown')}")
    
    # Fix 5: Use psutil library instead of subprocess for safer process information retrieval
    try:
        process_names = []
        for proc in psutil.process_iter(['name']):
            if name in proc.info['name']:
                process_names.append(proc.info['name'])
                
        return jsonify({"success": True, "names": process_names})
    except Exception as e:
        current_app.logger.error(f"Error in process lookup: {str(e)}")
        return jsonify({"error": "Failed to retrieve process information"})

def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
