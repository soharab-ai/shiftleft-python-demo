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
    redirect_url = request.args.get("redirect_to", "/")
    
    if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return jsonify({"error": "Invalid input"}), 400
    
    try:
        # Use safer approach without shell=True
        res = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=False
        )
        
        # Filter the output in Python instead of shell commands
        matching_processes = []
        for line in res.stdout.splitlines():
            if name in line:
                parts = line.split()
                if len(parts) >= 11:
                    matching_processes.append(parts[10])
        
        # Safe URL redirection - only allow relative URLs or specific domains
        if redirect_url:
            # Only allow relative URLs starting with / for internal redirects
            if redirect_url.startswith('/'):
                return redirect(redirect_url)
            else:
                # For security, default to home page if external URL is provided
                return redirect('/')
        
        return jsonify({"processes": matching_processes})
    except subprocess.SubprocessError:
        return jsonify({"error": "Command execution failed"}), 500

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
