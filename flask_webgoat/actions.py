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
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "name parameter is required"})
    
    # Add input validation - reject inputs with special characters
    if re.search(r'[;<>&|()$[]`]', name):
        return jsonify({"error": "Invalid characters in name parameter"})
    
    # Use psutil instead of subprocess for secure process listing
    processes = []
    # Limit results to prevent DoS issues
    max_results = 100
    result_count = 0
    
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            if name in proc.info['name'] and result_count < max_results:
                processes.append(proc.info)
                result_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Implement simple rate limiting using session
    current_time = int(time.time())
    last_request_time = session.get('last_process_request', 0)
    
    if current_time - last_request_time < 2:  # Limit to one request every 2 seconds
        return jsonify({"error": "Rate limit exceeded. Please wait before trying again."})
    
    session['last_process_request'] = current_time
    
    return jsonify({
        "success": True, 
        "processes": processes,
        "limited": result_count >= max_results  # Indicate if results were limited
    })

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
