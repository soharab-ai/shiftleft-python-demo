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
# Global rate limiting cache
_rate_limit_cache = null

# Whitelist of permitted process names
ALLOWED_PROCESS_NAMES = {
    "python", "nginx", "apache2", "httpd", "mysql", "postgres", 
    "mongodb", "redis", "node", "java", "tomcat", "firefox", "chrome"
}

# OS Command abstraction wrapper
class SystemCommandExecutor:
    @staticmethod
    def find_processes(name, timeout=3):
        """Safely execute process search with timeout"""
        try:
            # Use pgrep for process identification - more restricted approach
@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    try:
        # Validate content type to restrict potential attacks
        if request.content_type and not request.content_type.startswith('application/x-www-form-urlencoded'):
            return jsonify({"success": False, "error": "Invalid content type"}), 415
            
        pickled = request.form.get('pickled')
        if not pickled:
            return jsonify({"success": False, "error": "Missing required parameter"}), 400
            
        # Define expected data structure using Marshmallow schema
        class ExpectedDataSchema(Schema):
            # Define expected structure - adjust fields based on your actual data needs
            name = fields.String(required=True)
            value = fields.String(required=True)
            # Add more fields as needed
        
        try:
            # Verify signature and decode data
            decoded = verify_and_load(pickled, request.app.config['SECRET_KEY'])
            
            # Validate data against schema
            schema = ExpectedDataSchema()
            validated_data = schema.load(decoded)
            
            return jsonify({"success": True, "description": str(validated_data)})
        except ValidationError as err:
            return jsonify({"success": False, "error": f"Schema validation error: {err.messages}"}), 400
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
            
    except base64.binascii.Error:
        return jsonify({"success": False, "error": "Invalid base64 encoding"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid data format: {str(e)}"}), 400

def verify_and_load(signed_data, secret_key):
    """
    Verify the digital signature and load the data if valid.
    
    Args:
        signed_data: Base64-encoded string containing signature and serialized data
        secret_key: Secret key used for generating/verifying signatures
    
    Returns:
        Deserialized data if signature is valid
        
    Raises:
        ValueError if signature is invalid or data format is incorrect
    """
    try:
        decoded = base64.urlsafe_b64decode(signed_data).decode('utf-8')
        # Extract signature and serialized data
        if ':' not in decoded:
            raise ValueError("Invalid data format - signature separator not found")
            
        signature, serialized = decoded.split(':', 1)
        # Verify signature
        expected_sig = hmac.new(secret_key.encode(), serialized.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Invalid signature - data may have been tampered with")
            
        # Deserialize with safe JSON loads
        return json.loads(serialized)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format in payload")

# Helper function for creating signed data (to be used when creating the serialized data)
def sign_data(data, secret_key):
    """
    Serialize data to JSON and add a digital signature.
    
    Args:
        data: The data to be serialized and signed
        secret_key: Secret key used for generating signatures
    
    Returns:
        Base64-encoded string containing signature and serialized data
    """
    serialized = json.dumps(data)
    signature = hmac.new(secret_key.encode(), serialized.encode(), hashlib.sha256).hexdigest()
    combined = f"{signature}:{serialized}"
    return base64.urlsafe_b64encode(combined.encode('utf-8'))

            )
            return res.stdout.splitlines()
        except subprocess.TimeoutExpired:
            logging.warning(f"Process search for '{name}' timed out")
            return []
        except Exception as e:
            logging.error(f"Error executing process search: {str(e)}")
            return []

# Rate limiting decorator
def rate_limit(max_calls, time_frame):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = get_remote_address()
            current_time = time.time()
            
            # Clean up expired entries
            for ip in list(_rate_limit_cache.keys()):
                if current_time - _rate_limit_cache[ip]["timestamp"] > time_frame:
                    del _rate_limit_cache[ip]
            
            if client_ip in _rate_limit_cache:
                entry = _rate_limit_cache[client_ip]
                if entry["count"] >= max_calls:
                    logging.warning(f"Rate limit exceeded for IP: {client_ip}")
                    return jsonify({"error": "Rate limit exceeded. Try again later."})
                entry["count"] += 1
            else:
                _rate_limit_cache[client_ip] = {"count": 1, "timestamp": current_time}
                
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Asynchronous process search
async def async_process_search(name):
    # Create executor for running blocking code
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, SystemCommandExecutor.find_processes, name, 3)
    return results

@rate_limit(max_calls=5, time_frame=60)  # Added rate limiting: 5 calls per minute
def grep_processes():
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"})
    
    # Input validation - only allow alphanumeric characters and limited symbols
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
        # Added security logging for rejected requests
        logging.warning(f"Invalid process name requested: {name} from IP: {get_remote_address()}")
        return jsonify({"error": "invalid characters in name parameter"})
    
    # Defense-in-depth: Whitelist approach
    if name not in ALLOWED_PROCESS_NAMES:
        logging.warning(f"Attempt to search non-whitelisted process: {name} from IP: {get_remote_address()}")
        return jsonify({"error": "process name not in allowed list"})
    
    try:
        # Use asynchronous processing for better performance
        process_results = asyncio.run(async_process_search(name))
        
        # Process the output in Python
        names = []
        for line in process_results:
            parts = line.strip().split(None, 1)
            if len(parts) > 1:
                pid, proc_name = parts
                names.append(proc_name)
        
        # Log successful searches
        logging.info(f"Successful process search for '{name}' returned {len(names)} results")
        return jsonify({"success": True, "names": names})
        
    except Exception as e:
        # Enhanced error handling
        logging.error(f"Error in grep_processes: {str(e)}")
        return jsonify({"error": f"An internal error occurred: {str(e)}"})

            
# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Define schema for expected data
EXPECTED_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "metadata": {"type": "object"}
    },
    "required": ["description"]
}

def validate_expected_structure(data):
    """Validate that the data has the expected structure"""
    try:
        jsonschema.validate(data, EXPECTED_SCHEMA)
        return True
    except jsonschema.exceptions.ValidationError:
        return False

@limiter.limit("10 per minute")  # Added rate limiting to prevent DoS attacks
def deserialized_descr():
    # Added content type verification
    if request.content_type != 'application/json':
        return jsonify({"error": "Expected Content-Type: application/json"})
    
    # Added input validation layer
    data_json = request.form.get('data')
    if not data_json or not isinstance(data_json, str):
        return jsonify({"error": "Invalid data format"})
    
    try:
        # Using JSON instead of pickle for deserialization to prevent arbitrary code execution
        deserialized = json.loads(data_json)
        
        # Added schema validation to ensure expected data structure
        if not validate_expected_structure(deserialized):
            return jsonify({"error": "Invalid data structure"})
            
        return jsonify({"success": True, "description": str(deserialized)})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"})
    except jsonschema.exceptions.ValidationError:
        return jsonify({"error": "Data failed schema validation"})

            
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
