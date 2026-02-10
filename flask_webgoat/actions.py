import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
# Configure security logger
logger = logging.getLogger("security")
handler = logging.FileHandler("security.log")
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('user_logs.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS user_logs 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, original_filename TEXT, 
                  safe_filename TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    return conn

# Define allowed directories mapping
ALLOWED_DIRECTORIES = {
    "logs": Path("data/logs"),
    "user_data": lambda user_id: Path(f"data/{str(user_id)}")
}

# Content validation function
def is_safe_content(content):
    # Check for potentially dangerous patterns
    dangerous_patterns = [
        r"<script",
        r"evals*(",
        r"document.cookie"
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False
    return True

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
    
    dir_type = request.form.get("dir_type", "user_data")
    user_id = user_info[0]
    
    # Security logging for access attempts
    logger.info(f"File write attempt: {filename_param} by user {user_id}")
    
    # Content validation to prevent malicious data
    if not is_safe_content(text_param):
        logger.warning(f"Unsafe content detected in submission by user {user_id}")
        return jsonify({"error": "Content contains potentially unsafe data"})
        
    try:
        # OPTION 1: Database Storage (primary method)
        # Generate UUID-based filename for secure storage
        safe_uuid_filename = f"{uuid.uuid4()}_{secure_filename(filename_param)}.txt"
        
        # Store data in database
        conn = get_db_connection()
        conn.execute("INSERT INTO user_logs (user_id, original_filename, safe_filename, content) VALUES (?, ?, ?, ?)",
                    (user_id, filename_param, safe_uuid_filename, text_param))
        conn.commit()
        conn.close()
        
        # OPTION 2: Also store in filesystem with secure path handling
        # Get directory from mapping
        dir_path = ALLOWED_DIRECTORIES.get(dir_type)
        if callable(dir_path):
            dir_path = dir_path(user_id)
            
        if not dir_path:
            logger.warning(f"Invalid directory type requested: {dir_type} by user {user_id}")
            return jsonify({"error": "Invalid directory type"})
            
        # Create directory if it doesn't exist
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Use UUID-based filename to eliminate path traversal risk
        file_path = dir_path / safe_uuid_filename
        
        # Verify the resolved path is within the intended directory
        if not file_path.resolve().is_relative_to(dir_path.resolve()):
            logger.warning(f"Path traversal attempt detected: {filename_param} by user {user_id}")
            return jsonify({"error": "Invalid file path"})
            
        # Write file securely
        with file_path.open("w", encoding="utf-8") as open_file:
            open_file.write(text_param)
            
        logger.info(f"Successfully saved log entry for user {user_id}: {safe_uuid_filename}")
        return jsonify({"success": True, "filename": safe_uuid_filename})
        
    except Exception as e:
        logger.error(f"Error in log_entry: {str(e)} for user {user_id}")
        return jsonify({"error": "Failed to save log entry"})

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
