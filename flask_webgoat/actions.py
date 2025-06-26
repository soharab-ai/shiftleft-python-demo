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
# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@bp.route("/deserialized_descr", methods=["POST"])
@limiter.limit("10 per minute")  # Added rate limiting to prevent DoS attacks
def deserialized_descr():
    json_data = request.form.get('data')
    signature = request.form.get('signature')
    
    # Added integrity check using HMAC to verify data hasn't been tampered with
    if not signature or not hmac.compare_digest(
        hmac.new(bp.config['SECRET_KEY'].encode(), json_data.encode(), hashlib.sha256).hexdigest(),
        signature
    ):
        return jsonify({"error": "Data integrity check failed"}), 403
        
    try:
        # Use JSON instead of pickle for safe deserialization
        deserialized = json.loads(json_data)
        
        # Added schema validation to ensure the JSON conforms to expected structure
        schema = {
            "type": "object",
            "properties": {
                "id": {"type": "number"},
                "name": {"type": "string"},
                "description": {"type": "string"}
            },
            "required": ["id", "name"],
            "additionalProperties": False  # Reject unexpected properties
        }
        
        validate(instance=deserialized, schema=schema)
        return jsonify({"success": True, "description": str(deserialized)})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid data format"}), 400
    except ValidationError as e:
        return jsonify({"error": f"Schema validation failed: {str(e)}"}), 400
