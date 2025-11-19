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
# Setup secure logging
logger = logging.getLogger(__name__)
handler = logging.FileHandler('security.log')
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Rate limiting decorator
def rate_limit(max_calls, time_frame):
    calls = null
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            ip = request.remote_addr
            
            if ip not in calls:
                calls[ip] = []
            
            # Remove old calls outside the time frame
            calls[ip] = [t for t in calls[ip] if t > now - time_frame]
            
            if len(calls[ip]) >= max_calls:
                logger.warning(f"Rate limit exceeded for IP: {ip}")
                return jsonify({"error": "Too many requests. Please try again later."}), 429
            
            calls[ip].append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Input validation function for process names
def validate_process_name(name):
    """
    Validates a process name to ensure it only contains safe characters.
    
    Args:
        name (str): The process name to validate
        
    Returns:
        bool: True if the name is valid, False otherwise
    """
    if not name:
        return False
    
    # Use bleach to sanitize input - only allow alphanumeric + limited symbols
    sanitized = bleach.clean(name, strip=True)
    valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    
    return sanitized == name and all(char in valid_chars for char in name)

@rate_limit(max_calls=10, time_frame=60)  # 10 calls per minute
def grep_processes():
    # Check user permissions (simplified example - in real app, would use proper auth framework)
    if 'user_role' not in session or session['user_role'] != 'admin':
        logger.warning(f"Unauthorized access attempt from IP: {request.remote_addr}")
        return jsonify({"error": "Access denied"}), 403
        
    name = request.args.get("name")
    
    # Log the request (sanitized)
    safe_name = bleach.clean(str(name), strip=True) if name else ""
    logger.info(f"Process search requested for: {safe_name}")
    
    # Validate input using dedicated validation function
    if not validate_process_name(name):
        logger.warning(f"Invalid process name format attempted: {safe_name}")
        return jsonify({"error": "Invalid request parameters"}), 400
    
    try:
        # Using psutil library instead of subprocess for process management
        process_names = []
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name']
                if name in proc_name:
                    process_names.append(proc_name)
                # Also check command line for the process name
                elif proc_info['cmdline'] and any(name in cmd for cmd in proc_info['cmdline']):
                    process_names.append(proc_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return jsonify({"success": True, "names": process_names})
    
    except Exception as e:
        # Generic error message to user, detailed logging for debugging
        logger.error(f"Error in grep_processes: {str(e)}")
        return jsonify({"error": "An error occurred while processing your request"}), 500


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
