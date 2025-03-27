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

    # MITIGATION 1: Use whitelist approach instead of blacklist filtering
    if not re.match(r'^[a-zA-Z0-9_-]+$', filename_param):
        return jsonify({"error": "Invalid filename - only alphanumeric characters, underscores, and hyphens allowed"})
    
    # MITIGATION 2: Normalize paths before validation
    normalized_path = os.path.normpath(filename_param)
    if normalized_path != os.path.basename(normalized_path):
        return jsonify({"error": "Invalid filename - path traversal attempt detected"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir(parents=True, exist_ok=True)

    # MITIGATION 3: Use UUID-based filename approach
    unique_id = uuid.uuid4()
    
    # MITIGATION 4: Use dedicated sanitization library
    sanitized_filename = secure_filename(filename_param)
    safe_filename = f"{unique_id}_{sanitized_filename}.txt"
    
    # Use proper path joining with pathlib instead of string concatenation
    final_path = user_dir_path.joinpath(safe_filename)
    
    # MITIGATION 5: Add output path validation
    if os.path.commonpath([str(final_path.absolute()), str(user_dir_path.absolute())]) != str(user_dir_path.absolute()):
        return jsonify({"error": "Path traversal attempt detected"})
    
    with final_path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})



@bp.route("/grep_processes")
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
