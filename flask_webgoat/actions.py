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
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    with path.open("w", encoding="utf-8") as open_file:
        # vulnerability: Directory Traversal
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
# Configure logging
logger = logging.getLogger(__name__)
handler = logging.FileHandler('application.log')
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per minute", "50 per hour"]
)

# Allowlist of processes that can be searched
ALLOWED_PROCESS_PATTERNS = [
    "python", "flask", "nginx", "apache", "mysql", "postgres"
]

def grep_processes():
    # Apply rate limiting to this endpoint
    @limiter.limit("5 per minute")
    def rate_limited_function():
        name = request.args.get("name")
        client_ip = get_remote_address()
        
        # Log the search request (with sanitized input)
        safe_name = re.sub(r'[^\w]', '', str(name)) if name else ''
        logger.info(f"Process search request from {client_ip} for: {safe_name}")
        
        # Input validation: check if name is provided and in the allowlist
        if not name:
            return jsonify({"error": "Process name parameter is required"})
            
        # Check against allowlist instead of just regex validation
        if not any(pattern in name for pattern in ALLOWED_PROCESS_PATTERNS):
            logger.warning(f"Blocked search for non-allowed process: {safe_name} from {client_ip}")
            return jsonify({"error": "Process name not in allowed list"})
        
        try:
            # Using psutil library instead of subprocess for safer process listing
            process_names = []
            for proc in psutil.process_iter(['name', 'username']):
                process_info = proc.info
                # Filter by process name and optionally by user for least privilege
                if name in process_info['name']:
                    process_names.append(process_info['name'])
                    
            logger.info(f"Found {len(process_names)} matching processes")
            return jsonify({"success": True, "names": process_names})
            
        except Exception as e:
            logger.error(f"Error in process listing: {str(e)}")
            return jsonify({"error": "Failed to retrieve process list", "details": str(e)})
    
    return rate_limited_function()

def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
