import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    # Set up logging for security monitoring
    logging.basicConfig(filename='security.log', level=logging.INFO)
    
    # Track request for monitoring
    logging.info(f"File operation requested from IP: {get_remote_address()}")
    
    user_info = session.get("user_info", None)
    if user_info is None:
        logging.warning(f"Unauthorized access attempt: no user_info in session from {get_remote_address()}")
        return jsonify({"error": "no user_info found in session"})
    
    access_level = user_info[2]
    if access_level > 2:
        logging.warning(f"Insufficient access level attempt by user ID: {user_info[0]}")
        return jsonify({"error": "access level < 2 is required for this action"})
    
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})
    
    # Implement size limit for text input to prevent DoS attacks
    if len(text_param) > 10000:  # 10KB limit
        logging.warning(f"Oversized content attempt by user ID: {user_info[0]}")
        return jsonify({"error": "text content exceeds maximum allowed size"})
    
    # Validate text content for malicious patterns
    if re.search(r'<script|javascript:|eval\(|document\.cookie', text_param, re.IGNORECASE):
        logging.warning(f"Potentially malicious content detected from user ID: {user_info[0]}")
        return jsonify({"error": "potentially malicious content detected"})
    
    user_id = user_info[0]
    
    # Generate UUID instead of using user-provided filename
    unique_filename = str(uuid.uuid4())
    
    # Create content hash for content-addressed storage
    content_hash = hashlib.md5(text_param.encode()).hexdigest()
    safe_filename = f"{unique_filename}_{content_hash}"
    
    # Properly construct directory path using Path's joining capabilities
    user_dir_path = Path("data") / str(user_id)
    if not user_dir_path.exists():
        user_dir_path.mkdir(parents=True, exist_ok=True)

    # Use .txt extension to enforce file type whitelist
    filename = safe_filename + ".txt"
    path = user_dir_path / filename
    
    # Ensure the final path is within the intended directory
    if not str(path.resolve()).startswith(str(user_dir_path.resolve())):
        logging.warning(f"Path traversal attempt detected by user ID: {user_info[0]}")
        return jsonify({"error": "invalid file path"})
    
    # Rate limiting check - basic implementation
    last_write = session.get("last_file_write", 0)
    current_time = time.time()
    if current_time - last_write < 1:  # 1 second between writes
        logging.warning(f"Rate limit exceeded by user ID: {user_info[0]}")
        return jsonify({"error": "rate limit exceeded, please try again later"})
    
    session["last_file_write"] = current_time
    
    try:
        with path.open("w", encoding="utf-8") as open_file:
            open_file.write(text_param)
        
        # Log successful write operation
        logging.info(f"File {filename} created successfully by user ID: {user_info[0]}")
        
        return jsonify({
            "success": True,
            "file_id": safe_filename
        })
    except Exception as e:
        logging.error(f"Error writing file: {str(e)}")
        return jsonify({"error": "Failed to write file"})

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
