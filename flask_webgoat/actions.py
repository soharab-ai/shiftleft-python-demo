import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)

def is_safe_filename(filename):
    """Validate filename to prevent directory traversal attacks."""
    # FIX: Add null byte detection to prevent null-byte injection attacks
    if '\x00' in filename or '\0' in filename:
        return False
    # FIX: Add unicode normalization to prevent homograph attacks
    filename = unicodedata.normalize('NFKC', filename)
    # Only allow alphanumeric characters, hyphens, and underscores
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', filename))

    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    # FIX: Validate filename to prevent directory traversal attacks
    if not is_safe_filename(filename_param):
        return jsonify({"error": "Invalid filename. Only alphanumeric characters, hyphens, and underscores are allowed"})

    # FIX: Add filename length validation to prevent buffer overflow attempts
    if len(filename_param) > 50:
        return jsonify({"error": "Filename too long"})
    
    # FIX: Block OS-specific reserved names to prevent Windows-specific vulnerabilities
    if filename_param.upper() in ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']:
        return jsonify({"error": "Reserved filename"})
    
    # FIX: Explicit check for path traversal sequences as additional defense layer
    if '..' in filename_param or '/' in filename_param or '\\' in filename_param:
        return jsonify({"error": "Invalid characters in filename"})

    user_id = user_info[0]
    # FIX: Use Path operations instead of string concatenation
    user_dir = Path("data") / str(user_id)
    # FIX: Use parents=True and exist_ok=True for safer directory creation
    if not user_dir.exists():
        user_dir.mkdir(parents=True, exist_ok=True)

    filename = filename_param + ".txt"
    
    # FIX: Implement allowlist for file extensions
    if not filename.endswith('.txt'):
        return jsonify({"error": "Invalid file type"})
    
    # FIX: Use Path operations to construct the file path safely
    path = (user_dir / filename).resolve()
    
    # FIX: Ensure the resolved path is within the user directory to prevent directory traversal
    try:
        path.relative_to(user_dir.resolve())
    except ValueError:
        return jsonify({"error": "Invalid file path"})
    
    # FIX: Add symbolic link detection to prevent symlink-based bypasses
    if path.is_symlink():
        return jsonify({"error": "Symbolic links not allowed"})
    
    # FIX: Add permission check before writing to prevent unauthorized file overwrites
    if path.exists() and not os.access(path, os.W_OK):
        return jsonify({"error": "Permission denied"})
    
    with path.open("w", encoding="utf-8") as open_file:
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

