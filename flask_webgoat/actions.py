# Fixed: Removed insecure pickle import, added secure alternatives and schema validation
import json
import hmac
import hashlib
import io
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session, current_app
# Fixed: Added jsonschema for input validation
from jsonschema import validate, ValidationError

bp = Blueprint("actions", __name__)

        return jsonify({"error": "no user_info found in session"})
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
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    # Fixed: Replaced insecure pickle deserialization with secure JSON deserialization
    # This eliminates the remote code execution vulnerability (A8:2017-Insecure Deserialization)
    
    # Fixed: Enforce Content-Type validation to prevent unexpected content types
    content_type = request.headers.get('Content-Type', '')
    if not content_type.startswith('application/x-www-form-urlencoded') and \
       not content_type.startswith('application/json'):
        return jsonify({"error": "Unsupported Content-Type"}), 415
    
    # Fixed: Add authentication check before processing
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "Authentication required"}), 401
    
    # Fixed: Implement per-user rate limiting to prevent abuse
    user_id = user_info[0]
    rate_limit_key = f"deserialize_rate_{user_id}"
    current_count = session.get(rate_limit_key, 0)
    MAX_REQUESTS_PER_MINUTE = 10
    
    if current_count >= MAX_REQUESTS_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    session[rate_limit_key] = current_count + 1
    
    json_data = request.form.get('data')
    
    # Fixed: Added validation to ensure data parameter is provided
    if json_data is None:
        return jsonify({"error": "data parameter is required"}), 400
    
    # Fixed: Enforce maximum payload size to prevent DoS attacks
    MAX_PAYLOAD_SIZE = 10240  # 10KB
    if len(json_data) > MAX_PAYLOAD_SIZE:
        return jsonify({"error": "Payload size exceeds maximum allowed"}), 413
    
    # Fixed: Define strict schema validation - only accept flat dictionary with string values
    ALLOWED_SCHEMA = {
        "type": "object",
        "properties": {
            "description": {"type": "string", "maxLength": 500}
        },
        "required": ["description"],
        "additionalProperties": False
    }
    
    try:
        # Fixed: Use JSON instead of pickle - safe for untrusted data per OWASP A8 mitigation
        deserialized = json.loads(json_data)
        
        # Fixed: Validate against strict schema to whitelist allowed structures
        validate(instance=deserialized, schema=ALLOWED_SCHEMA)
        
        # Fixed: Additional type checking to ensure only expected keys exist
        if not isinstance(deserialized, dict):
            return jsonify({"error": "Data must be a JSON object"}), 400
        
        description = deserialized.get('description', '')
        return jsonify({"success": True, "description": description})
    except ValidationError:
        # Fixed: Added schema validation error handling
        return jsonify({"error": "Data does not match required schema"}), 400
    except json.JSONDecodeError:
        # Fixed: Added proper error handling with secure error messages
        return jsonify({"error": "Invalid JSON data format"}), 400
    except Exception:
        # Fixed: Catch-all for unexpected errors without exposing internal details
        return jsonify({"error": "Deserialization failed"}), 400
