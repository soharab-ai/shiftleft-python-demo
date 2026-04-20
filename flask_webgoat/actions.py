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
    
    # FIX: Replace direct filename input with file identifier mapping
    file_id = request.form.get("file_id")
    if file_id is None:
        return jsonify({"error": "file_id parameter is required"})
    
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    # FIX: Implement allowlist-based file mapping with predefined identifiers
    ALLOWED_FILES = {
        "report": "user_report.txt",
        "log": "user_log.txt",
        "notes": "user_notes.txt",
        "summary": "user_summary.txt",
        "data": "user_data.txt"
    }
    
    # FIX: Validate that file_id exists in the allowlist
    if file_id not in ALLOWED_FILES:
        return jsonify({"error": "Invalid file identifier"})
    
    # FIX: Retrieve the safe filename from allowlist (no user-controlled filename)
    filename = ALLOWED_FILES[file_id]

    user_id = user_info[0]
    # FIX: Use Path.resolve() to get canonical absolute path for base directory
    base_dir = Path("data").resolve()
    user_dir = base_dir / str(user_id)
    
    # FIX: Create directory with parents=True and exist_ok=True for safer directory creation
    if not user_dir.exists():
        user_dir.mkdir(parents=True, exist_ok=True)

    # FIX: Use os.path.basename() as defense-in-depth to ensure only filename component is used
    safe_filename = os.path.basename(filename)
    # FIX: Resolve the file path to get canonical absolute path
    file_path = (user_dir / safe_filename).resolve()
    
    # FIX: Verify the resolved path is within the intended user directory using relative_to()
    try:
        file_path.relative_to(user_dir)
    except ValueError:
        return jsonify({"error": "Invalid file path"})
    
    with file_path.open("w", encoding="utf-8") as open_file:
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
