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
    
    # Fix: Added input validation to prevent command injection
    if name is None or not re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
        return jsonify({"error": "invalid input"})
    
    # Fix: Removed shell=True and using a list of arguments instead of string concatenation
    # Fix: Execute ps aux directly and handle filtering in Python
    res = subprocess.run(
        ["ps", "aux"], 
        shell=False,
        capture_output=True,
        text=True
    )
    
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    
    # Fix: Process filtering in Python instead of shell commands
    lines = res.stdout.splitlines()
    matching_lines = [line for line in lines if name in line]
    process_names = [line.split()[10] if len(line.split()) > 10 else "" for line in matching_lines]
    
    return jsonify({"success": True, "names": process_names})

def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
