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
    # Constants for security controls
    MAX_FILE_SIZE = 1024 * 1024  # 1MB maximum file size
    MAX_REQUESTS_PER_MINUTE = 10  # Rate limiting
    
    # Rate limiting implementation
    rate_limit_tracker = defaultdict(list)
    
    # Implement rate limiting check
    current_time = time.time()
    user_requests = [t for t in rate_limit_tracker.get(user_dir, []) if current_time - t < 60]
    rate_limit_tracker[user_dir] = user_requests + [current_time]
    
    if len(user_requests) >= MAX_REQUESTS_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    
    if not user_dir_path.exists():
        user_dir_path.mkdir()
    
    # Check file size limit
    if len(text_param) > MAX_FILE_SIZE:
        return jsonify({"error": "File too large"}), 400
    
    # Implement allowlist pattern approach instead of blacklisting
    def validate_filename(filename):
        # Only allow alphanumeric, underscore, hyphen, and period characters
        return bool(re.match(r'^[a-zA-Z0-9_\-\.]+$', filename))
    
    # Generate secure random filename instead of using user input directly
    safe_uuid = str(uuid.uuid4())
    
    if filename_param and validate_filename(filename_param):
        # If valid filename provided, use it with the UUID as prefix
        filename = f"{safe_uuid}_{filename_param}.txt"
    else:
        # Otherwise just use the UUID
        filename = f"{safe_uuid}.txt"
    
    # Use os.path.realpath() for path validation
    path = Path(os.path.join(user_dir, filename))
    
    # Alternative path validation that works across Python versions
    canonical_path = os.path.realpath(str(path))
    base_dir = os.path.realpath(user_dir)
    
    if not canonical_path.startswith(base_dir):
        # Path traversal attempt detected, reject the request
        return jsonify({"error": "Invalid path detected"}), 400
        
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    
    # Add file type verification after writing
    file_type = magic.from_file(str(path), mime=True)
    if not file_type.startswith('text/'):
        os.remove(str(path))  # Remove potentially dangerous file
        return jsonify({"error": "Invalid file type detected"}), 400
    
    return jsonify({"success": True, "filename": filename})



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
