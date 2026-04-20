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
@limiter.limit("10 per minute") # Added rate limiting to prevent abuse
def grep_processes():
    # Added logging to track potential abuse attempts
    logger.info(f"Process query requested from IP: {get_remote_address()}")
    
    name = request.args.get("name")
    
    # Implemented whitelist-based approach for allowed process names
    allowed_process_names = ["apache2", "nginx", "mysql", "postgres", "python", "node", "java"]
    
    if not name or name not in allowed_process_names:
        logger.warning(f"Unauthorized process query attempt: {name}")
        return jsonify({"error": "unauthorized process query"})
    
    # Using psutil library instead of subprocess for secure process information retrieval
    result = []
    try:
        for proc in psutil.process_iter(['name']):
            try:
                if name in proc.info['name']:
                    result.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        logger.error(f"Error querying processes: {str(e)}")
        return jsonify({"error": "failed to get process list"})
               
    return jsonify({"processes": result})

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
