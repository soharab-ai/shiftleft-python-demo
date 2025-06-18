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
# Define a schema for expected JSON data
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "metadata": {
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "timestamp": {"type": "number"}
            }
        }
    },
    "required": ["description"]
}

@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    # Changed parameter name from 'pickled' to 'data' to reflect its new purpose
    serialized_data = request.form.get('data')
    if not serialized_data:
        return jsonify({"success": False, "error": "No data provided"})
    
    try:
        # Use JSON instead of pickle for secure deserialization
        data = base64.urlsafe_b64decode(serialized_data).decode('utf-8')
        deserialized = json.loads(data)
        
        # Added schema validation to further enhance security
        jsonschema.validate(instance=deserialized, schema=JSON_SCHEMA)
        
        return jsonify({"success": True, "description": str(deserialized)})
    except base64.binascii.Error:
        return jsonify({"success": False, "error": "Invalid base64 encoding"})
    except json.JSONDecodeError as e:
        return jsonify({"success": False, "error": f"JSON decode error: {str(e)}"})
    except jsonschema.exceptions.ValidationError as e:
        return jsonify({"success": False, "error": f"Schema validation error: {str(e)}"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Error processing data: {str(e)}"})
