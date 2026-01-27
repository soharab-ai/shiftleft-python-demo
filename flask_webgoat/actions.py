import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database-like structure to store filename mappings (in production, use a real database)
filename_mappings = null

def sanitize_content(content, max_length=10000):
    """Sanitize and validate the content to prevent malicious input"""
    # Check for content size limits to prevent DoS attacks
    if content and len(content) > max_length:
        raise ValueError(f"Content exceeds maximum length of {max_length} characters")
    
    # Use bleach to sanitize content
    return bleach.clean(content)

def save_filename_mapping(user_id, original_filename, secure_filename):
    """Store the mapping between user-provided filename and secure UUID filename"""
    if user_id not in filename_mappings:
        filename_mappings[user_id] = null
    
    timestamp = datetime.now().isoformat()
    filename_mappings[user_id][secure_filename] = {
        "original_name": original_filename,
        "created_at": timestamp
    }

@bp.route("/message", methods=["POST"])
@limiter.limit("10 per minute")  # Implement rate limiting for this endpoint
def log_entry():
    # Audit logging
    request_time = time.time()
    remote_addr = request.remote_addr
    
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

    # Validate and sanitize content
    try:
        sanitized_text = sanitize_content(text_param)
    except ValueError as e:
        return jsonify({"error": str(e)})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir(parents=True, exist_ok=True)

    # Generate a secure UUID-based filename instead of using user input
    secure_filename = str(uuid.uuid4()) + ".txt"
    path = user_dir_path / secure_filename
    
    # Store mapping between user-provided filename and secure filename
    save_filename_mapping(user_id, filename_param, secure_filename)
    
    # Write the sanitized content
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(sanitized_text)
    
    # Log the successful file operation for audit purposes
    print(f"User {user_id} created file {secure_filename} at {datetime.now().isoformat()} from {remote_addr}")
    
    return jsonify({"success": True, "filename": secure_filename})

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
