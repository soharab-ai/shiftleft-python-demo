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


# Define a schema for validating the deserialized data
class DataSchema(Schema):
    # Define expected fields here
    description = fields.String(required=True)
    # Add other expected fields as needed

# Define constants
MAX_SIZE = 10 * 1024  # 10KB limit
SECRET_KEY = "your-secret-key"  # Store securely in environment variables or config

@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    # Get the serialized data
    serialized = request.form.get('pickled')  # Keeping parameter name for backward compatibility
    
    # Check if data exists and is within size limits
    if not serialized or len(serialized) > MAX_SIZE:
        return jsonify({"success": False, "error": "Data exceeds size limit or is empty"}), 400
    
    # Choose which approach to use (JSON or JWT)
    use_jwt = request.args.get('use_jwt', 'false').lower() == 'true'
    
    try:
        if use_jwt:
            # JWT approach: Verify and decode the token
            deserialized = jwt.decode(serialized, SECRET_KEY, algorithms=["HS256"])
        else:
            # JSON approach: Decode base64 and parse as JSON
            decoded_data = base64.urlsafe_b64decode(serialized).decode('utf-8')
            raw_data = json.loads(decoded_data)
            
            # Validate against schema
            schema = DataSchema()
            deserialized = schema.load(raw_data)
        
        return jsonify({"success": True, "description": str(deserialized)})
    except ValidationError as e:
        return jsonify({"success": False, "error": "Schema validation failed", "details": e.messages}), 400
    except jwt.InvalidTokenError as e:
        return jsonify({"success": False, "error": "Invalid JWT token"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid data format: {str(e)}"}), 400

