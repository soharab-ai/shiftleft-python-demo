import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
def log_entry():
    # Constants for validation
    MAX_TEXT_LENGTH = 10000
    FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
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
    
    # MITIGATION 4: Content validation for text parameter
    if len(text_param) > MAX_TEXT_LENGTH:
        return jsonify({"error": "Text content exceeds maximum allowed length"})
    
    # Additional content validation - check for dangerous patterns
    if contains_dangerous_patterns(text_param):
        return jsonify({"error": "Text content contains potentially dangerous patterns"})
    
    user_id = user_info[0]
    
    try:
        # MITIGATION 2: Using filesystem abstraction layer
        file_path = get_user_file_path(user_id, filename_param)
        
        # Write content to file using UUID-based name
        with file_path.open("w", encoding="utf-8") as open_file:
            open_file.write(text_param)
        
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"error": str(e)})

def contains_dangerous_patterns(text):
    """Check if text contains potentially harmful content"""
    dangerous_patterns = [
        r"<script",
        r"javascript:",
        r"eval\(",
        # Add more patterns as needed
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def get_user_file_path(user_id, filename):
    """
    MITIGATION 2: Filesystem abstraction layer
    Maps user requests to specific controlled locations
    """
    # MITIGATION 1: Whitelist validation for filename
    FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    if not FILENAME_PATTERN.match(filename):
        raise ValueError("Invalid filename format")
    
    storage_root = Path("data").resolve()
    user_dir_path = storage_root / str(user_id)
    
    if not user_dir_path.exists():
        user_dir_path.mkdir(parents=True)
    
    # MITIGATION 3: UUID-based file storage
    safe_uuid = str(uuid.uuid4())
    safe_filename = safe_uuid + ".txt"
    
    # Store mapping between original filename and UUID filename
    # In a real application, this would be stored in a database
    mapping_file = user_dir_path / "filename_mapping.txt"
    with mapping_file.open("a", encoding="utf-8") as f:
        f.write(f"{filename}:{safe_uuid}\n")
    
    file_path = user_dir_path / safe_filename
    
    # Double-check that path is still within user directory
    if not file_path.resolve().is_relative_to(user_dir_path.resolve()):
        raise ValueError("Invalid file path detected")
        
    return file_path

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
