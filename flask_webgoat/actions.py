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


@bp.route("/redirect")
def redirect_page():
    """
    Securely handle URL redirections by implementing a whitelist approach
    and validation for relative URLs.
    """
    destination = request.args.get("url", "")
    
    # Option 1: Use a whitelist of allowed destinations
    allowed_destinations = {
        "home": "/home",
        "profile": "/profile",
        "settings": "/settings",
        "dashboard": "/dashboard"
    }
    
    # If the destination is in our whitelist, redirect to the safe path
    if destination in allowed_destinations:
        return redirect(allowed_destinations[destination])
    
    # Option 2: Only allow relative URLs within our application
    if destination.startswith('/') and not destination.startswith('//'):
        # Additional validation to ensure it's a valid path in our application
        if re.match(r'^/[a-zA-Z0-9_/\-]+$', destination):
            # Add logging for audit purposes
            return redirect(destination)
    
    # If the URL was not in whitelist or a valid relative URL,
    # redirect to default page for safety
    return redirect("/default_page")

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
