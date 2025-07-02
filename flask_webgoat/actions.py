import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
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

    # Added content length restriction to prevent DoS attacks
    if len(text_param) > 10000:  # 10KB limit
        return jsonify({"error": "content too large"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    
    # Create user directory using file system abstraction
    try:
        # Using file system isolation with fs library
        user_fs = OSFS(user_dir, create=True)
    except Exception as e:
        return jsonify({"error": f"Failed to access file system: {str(e)}"})

    # Generate cryptographic filename instead of user input
    hash_obj = hashlib.md5((filename_param + str(time.time())).encode())
    safe_filename = hash_obj.hexdigest() + ".txt"
    
    try:
        # Write file using filesystem abstraction
        with user_fs.open(safe_filename, "w") as open_file:
            open_file.write(text_param)
        
        # Get the real file path for MIME type checking
        real_path = os.path.join(user_dir, safe_filename)
        
        # Validate file type using magic library
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(real_path)
        if not file_type.startswith('text/'):
            # Remove file if invalid type
            user_fs.remove(safe_filename)
            return jsonify({"error": "invalid file type"})
            
        return jsonify({"success": True, "filename": safe_filename})
    except Exception as e:
        return jsonify({"error": f"Failed to write file: {str(e)}"})
    finally:
        # Close filesystem
        user_fs.close()

def grep_processes():
def grep_processes():
    name = request.args.get("name")
    
    # Fix 1: Implement allowlisting instead of blocklisting approach
    ALLOWED_PROCESS_NAMES = ["apache2", "nginx", "mysql", "python", "firefox", "chrome", "systemd"]
    if name not in ALLOWED_PROCESS_NAMES:
        # Fix 4: Add security logging for potential abuse attempts
        current_app.logger.warning(f"Unauthorized process lookup attempt: {shlex.quote(name)} by user: {session.get('user_id', 'unknown')}")
        return jsonify({"error": "Unauthorized process name"})
    
    # Fix 2: Use shlex for proper command sanitization
    sanitized_name = shlex.quote(name)
    
    # Fix 4: Log legitimate process lookup attempts
    current_app.logger.info(f"Process lookup requested for: {sanitized_name} by user: {session.get('user_id', 'unknown')}")
    
@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    # Validate content type to prevent unexpected formats
    content_type = request.headers.get('Content-Type', '')
    if not ('application/x-www-form-urlencoded' in content_type or 'application/json' in content_type):
        return jsonify({"error": "Invalid Content-Type"}), 415
    
    # Get data from appropriate source based on content type
    if 'application/json' in content_type:
        json_data = request.json.get('data')
    else:
        json_data = request.form.get('data')
    
    # Check if data is missing
    if not json_data:
        return jsonify({"error": "Missing 'data' parameter"}), 400
        
    # Check if data is too large (1MB limit)
    if len(json_data) > 1048576:  # 1MB size limit
        return jsonify({"error": "Payload too large"}), 413
    
    try:
        # Define expected schema
        schema = {
            "type": "object",
            "properties": {
                "description": {"type": "string", "maxLength": 1000},
                "metadata": {"type": "object"}
            },
            "required": ["description"],
            "additionalProperties": False,
            "maxProperties": 2
        }
        
        # Parse with complexity limits
        deserialized = json.loads(json_data)
        
        # Validate against schema
        jsonschema.validate(instance=deserialized, schema=schema)
        
        # Map to safe object with allowed attributes
        class SafeData:
            def __init__(self, **kwargs):
                self.allowed_attrs = ['description', 'metadata']
                for key, value in kwargs.items():
                    if key in self.allowed_attrs:
                        setattr(self, key, value)
                        
        safe_object = SafeData(**deserialized)
        
        # Use proper encoding for output
        description = escape(getattr(safe_object, 'description', ''))
        
        # Set Content-Security-Policy header
        response = jsonify({
            "success": True, 
            "description": description
        })
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400
    except jsonschema.exceptions.ValidationError as e:
        return jsonify({"error": f"Schema validation failed: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An error occurred processing the request"}), 500

                
        return jsonify({"success": True, "names": process_names})
    except Exception as e:
        current_app.logger.error(f"Error in process lookup: {str(e)}")
        return jsonify({"error": "Failed to retrieve process information"})

def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
