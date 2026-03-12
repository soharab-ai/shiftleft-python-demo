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
@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    
    # FIX: Validate input parameter is provided
    if not name:
        return jsonify({"error": "name parameter is required"}), 400
    
    # FIX: Input validation - allow only alphanumeric, hyphens, and underscores to prevent command injection
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return jsonify({"error": "invalid name parameter"}), 400
    
    try:
        names = []
        # FIX: Use psutil to iterate processes instead of shell commands to eliminate command injection attack surface
        for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info
                # FIX: Check if name matches in process name or command line using safe string comparison
                if name.lower() in (proc_info.get('name') or '').lower():
                    exe_path = proc_info.get('exe') or ' '.join(proc_info.get('cmdline', []))
                    if exe_path:
                        names.append(exe_path)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # FIX: Skip processes that no longer exist or are inaccessible
                continue
                
        return jsonify({"success": True, "names": names})
        
    except Exception:
        # FIX: Generic error handling to avoid information disclosure
        return jsonify({"error": "process enumeration failed"}), 500

