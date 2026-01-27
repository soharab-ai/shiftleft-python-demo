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
# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Role-based access control decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin', False):
            logger.warning(f"Unauthorized access attempt to admin function from IP: {request.remote_addr}")
            return jsonify({"error": "Administrator privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def grep_processes():
    # Implement role-based access control
    @admin_required
    def protected_grep_processes():
        name = request.args.get("name")
        page = int(request.args.get("page", 1))
        limit = min(int(request.args.get("limit", 10)), 50)  # Limit results to prevent DoS
        
        # Input validation added to prevent command injection
        if not name:
            logger.warning(f"Missing name parameter from IP: {request.remote_addr}")
            return jsonify({"error": "name parameter is required"})
        
        # Using a whitelist approach instead of regex
        allowed_process_names = ["python", "java", "nginx", "apache2", "mysql", "postgres"]
        if name not in allowed_process_names:
            logger.warning(f"Invalid process name requested: {name} from IP: {request.remote_addr}")
            return jsonify({"error": "process name not allowed"})
        
        try:
            # Using psutil instead of subprocess for better security
            process_list = []
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '')
                    if name in proc_name:
                        process_list.append(proc_name)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Implement pagination
            total_results = len(process_list)
            start_idx = (page - 1) * limit
            end_idx = start_idx + limit
            paginated_results = process_list[start_idx:end_idx]
            
            logger.info(f"Process search completed for: {name}, found {total_results} results")
            return jsonify({
                "success": True, 
                "names": paginated_results,
                "page": page,
                "limit": limit,
                "total": total_results
            })
            
        except Exception as e:
            logger.error(f"Error in grep_processes: {str(e)}")
            return jsonify({"error": "An error occurred while fetching processes"}), 500
    
    return protected_grep_processes()

@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
