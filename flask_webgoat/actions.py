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
def deserialized_descr():
    # Define maximum size for serialized data to prevent DOS attacks
    MAX_SERIALIZED_SIZE = 8192  # 8KB limit
    
    serialized = request.form.get('pickled')
    
    # Input validation before deserialization
    if not serialized or not isinstance(serialized, str):
        return jsonify({"error": "Invalid input format"})
        
    # Size validation to prevent DOS attacks
    if len(serialized) > MAX_SERIALIZED_SIZE:
        return jsonify({"error": "Serialized data too large"})
    
    # Define schema for validation
    schema = {
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
        "required": ["description"],
        "additionalProperties": False
    }
    
    # Verify HMAC signature if provided
    hmac_key = request.application.config.get('SECRET_KEY', 'default-secret-key')
    received_signature = request.form.get('signature')
    if received_signature:
        calculated_signature = hmac.new(hmac_key.encode(), serialized.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(received_signature, calculated_signature):
            return jsonify({"error": "Invalid data signature"})
    
    try:
        # Decode base64 and deserialize from JSON instead of pickle
        decoded_data = base64.urlsafe_b64decode(serialized).decode('utf-8')
        
        # Use custom decoder with whitelisted types for more security
        class SafeJSONDecoder(json.JSONDecoder):
            def __init__(self, *args, **kwargs):
                super().__init__(object_hook=self.object_hook, *args, **kwargs)
            
            def object_hook(self, obj):
                # Only allow specific structures
                # This prevents unexpected object types
                return obj
                
        data = json.loads(decoded_data, cls=SafeJSONDecoder)
        
        # Perform schema validation
        validate(instance=data, schema=schema)
        
        return jsonify({"success": True, "description": str(data.get("description", ""))})
    except ValidationError as e:
        return jsonify({"error": "Schema validation failed", "details": str(e)})
    except base64.binascii.Error:
        return jsonify({"error": "Invalid base64 encoding"})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"})
    except Exception as e:
        return jsonify({"error": "Deserialization failed", "details": str(e)})
