import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
def log_entry():
    # Configure logging
    logging.basicConfig(
        filename='application.log',
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Define constants
    MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB limit
    
    user_info = session.get("user_info", None)
    if user_info is None:
        logging.warning("Attempted log_entry with no user_info in session")
        return jsonify({"error": "no user_info found in session"})
    
    access_level = user_info[2]
    if access_level > 2:
        logging.warning(f"User ID {user_info[0]} attempted access with insufficient privileges")
        return jsonify({"error": "access level < 2 is required for this action"})
    
    filename_param = request.form.get("filename")
    if filename_param is None:
        logging.warning(f"User ID {user_info[0]} attempted log_entry with missing filename")
        return jsonify({"error": "filename parameter is required"})
    
    text_param = request.form.get("text")
    if text_param is None:
        logging.warning(f"User ID {user_info[0]} attempted log_entry with missing text")
# Dictionary to track rate limiting
request_tracker = null

# Rate limiting decorator
def rate_limit(max_requests=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Initialize or clean up old entries
            if client_ip not in request_tracker:
                request_tracker[client_ip] = []
            
            # Remove requests outside the time window
            request_tracker[client_ip] = [t for t in request_tracker[client_ip] if current_time - t < window]
            
            # Check if rate limit exceeded
            if len(request_tracker[client_ip]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
            
            # Add current request timestamp
            request_tracker[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Whitelist of allowed process names for strict checking
ALLOWED_PROCESS_NAMES = {
    "chrome", "firefox", "safari", "apache2", "nginx", 
    "python", "node", "java", "vscode", "bash"
}

@rate_limit(max_requests=10, window=60)
def grep_processes():
    name = request.args.get("name")
    
    # Input validation - ensure name exists and matches allowed pattern
    if not name or not re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
        return jsonify({"error": "Invalid process name"}), 400
    
    # Optional: Strict whitelist checking
    if name not in ALLOWED_PROCESS_NAMES:
        return jsonify({"error": "Process name not in allowed list"}), 403
    
    # Using psutil instead of subprocess to eliminate shell command injection risk
    filtered_processes = []
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if name in proc.info['name']:
                filtered_processes.append(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    return jsonify({"success": True, "names": filtered_processes})

    # Use whitelisting approach - generate a safe filename with user ID and random token
    # First sanitize the original filename for logging purposes
    safe_original = secure_filename(filename_param)
    # Then create a completely generated safe name
    safe_filename = f"{user_id}_{secrets.token_hex(8)}.txt"
    
    # Properly join paths and create the file path
    file_path = user_dir_path / safe_filename
    
    # Store a mapping of the generated filename to original filename for reference
    filename_mapping_path = user_dir_path / "filename_mappings.txt"
    with open(filename_mapping_path, "a", encoding="utf-8") as mapping_file:
        mapping_file.write(f"{safe_filename}:{safe_original}\n")
    
    # Use temporary file for initial writing and virus scanning
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        temp_file.write(text_param.encode('utf-8'))
    
    try:
        # Perform virus scan on temp file
        cd = clamd.ClamdUnixSocket()
        scan_results = cd.scan(temp_path)
        if scan_results[temp_path][0] == 'FOUND':
            os.unlink(temp_path)  # Delete the temp file
            logging.warning(f"User ID {user_id} attempted to upload malicious content: {scan_results[temp_path][1]}")
            return jsonify({"error": "Potential malware detected in content"})
        
        # If scan is clear, move content to final location
        with open(temp_path, 'rb') as temp_file:
            with file_path.open("wb") as final_file:
                final_file.write(temp_file.read())
        
        # Remove the temp file
        os.unlink(temp_path)
        
        # Log successful file creation
        logging.info(f"User {user_id} successfully created file {safe_filename} (original: {safe_original})")
        
        return jsonify({
            "success": True,
            "filename": safe_filename,
            "original_filename": safe_original
        })
        
    except Exception as e:
        if os.path.exists(temp_path):
            os.unlink(temp_path)  # Clean up temp file on error
        logging.error(f"Error in log_entry for User {user_id}: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"})

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
