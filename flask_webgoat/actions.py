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
    next_url = request.args.get("next", "/")
    
    # Input validation - only allow alphanumeric characters and some safe symbols
    import re
    if not name or not re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
        return jsonify({"error": "invalid process name"})
    
    # Validate redirect URL to prevent open redirection
    if next_url:
        from urllib.parse import urlparse
        parsed_url = urlparse(next_url)
        # Only allow relative URLs or URLs to trusted domains
        if parsed_url.netloc and parsed_url.netloc not in {"trusted-domain.com", "localhost:5000"}:
            next_url = "/"
    
    try:
        # Using separate processes with pipes rather than shell commands
        ps_process = subprocess.Popen(["ps", "aux"], stdout=subprocess.PIPE)
        grep_process = subprocess.Popen(["grep", name], stdin=ps_process.stdout, stdout=subprocess.PIPE)
        ps_process.stdout.close()
        awk_process = subprocess.Popen(["awk", "{print $11}"], stdin=grep_process.stdout, stdout=subprocess.PIPE)
        grep_process.stdout.close()
        
        output = awk_process.communicate()[0]
        
        if not output:
            return jsonify({"error": "no stdout returned"})
            
        result = {"output": output.decode('utf-8')}
        
        # If this is meant to be a redirect after processing
        if "redirect" in request.args:
            from flask import redirect
            return redirect(next_url)
            
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

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
