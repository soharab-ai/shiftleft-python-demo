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
    # Validate content type
    if not request.is_json and not request.form:
        return jsonify({"success": False, "error": "Invalid content type"}), 415
    
    # Get data with size limitation (limit to 10KB)
    if request.is_json:
        if request.content_length and request.content_length > 10 * 1024:
            return jsonify({"success": False, "error": "Payload too large"}), 413
        data_string = request.get_json(silent=True)
    else:
        data_string = request.form.get('data')
        if data_string and len(data_string) > 10 * 1024:
            return jsonify({"success": False, "error": "Payload too large"}), 413
    
    if not data_string:
        return jsonify({"success": False, "error": "Missing data"}), 400
        
    # Using JSON for safe deserialization
    try:
        deserialized = json.loads(data_string) if isinstance(data_string, str) else data_string
        
        # Basic schema validation
        if not isinstance(deserialized, dict):
            return jsonify({"success": False, "error": "Invalid data structure"}), 400
            
        # Sanitize output before returning
        safe_description = str(deserialized).replace("<", "&lt;").replace(">", "&gt;")
        return jsonify({"success": True, "description": safe_description})
    except json.JSONDecodeError:
        return jsonify({"success": False, "error": "Invalid data format"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": "Processing error"}), 500

