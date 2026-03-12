import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)

def is_safe_filename(filename):
    """
    Validate filename to prevent directory traversal attacks.
    Only allows alphanumeric characters, hyphens, and underscores.
    Explicitly rejects path traversal patterns.
    """
    # MITIGATION: Reject empty filenames or exceed filesystem limits
    if len(filename) > 255 or len(filename) == 0:
        return False
    # Only allow alphanumeric characters, hyphens, and underscores - MITIGATION: Input validation
    if not re.match(r'^[a-zA-Z0-9_-]+$', filename):
        return False
    # Explicitly reject path traversal patterns - MITIGATION: Reject dangerous sequences
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    return True

        return jsonify({"error": "invalid filename - only alphanumeric, hyphens, and underscores allowed"})
    
    # MITIGATION: Prevent double extensions or null byte injection
    if '.' in filename_param or '\x00' in filename_param:
        return jsonify({"error": "invalid filename format"})
    
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    # MITIGATION: Use Path objects with proper separator handling
    user_dir = Path("data") / str(user_id)
    
    # MITIGATION: Ensure user directory exists with proper error handling
    try:
        user_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return jsonify({"error": "failed to create user directory"})
    
    # Construct the file path safely
    filename = filename_param + ".txt"
    path = user_dir / filename
    
    # MITIGATION: Resolve to absolute path and verify it's within the user directory
    try:
        resolved_path = path.resolve(strict=False)
        resolved_user_dir = user_dir.resolve(strict=False)
        
        # MITIGATION: Use os.path.commonpath() for robust path confinement check
        if os.path.commonpath([resolved_path, resolved_user_dir]) != str(resolved_user_dir):
            return jsonify({"error": "invalid path - directory traversal detected"})
        
        # MITIGATION: Double-check using relative_to for additional validation
        try:
            resolved_path.relative_to(resolved_user_dir)
        except ValueError:
            return jsonify({"error": "invalid path - directory traversal detected"})
        
        # MITIGATION: Verify no symlinks in the path to prevent symlink-based traversal
        if resolved_path.is_symlink():
            return jsonify({"error": "symbolic links not allowed"})
        for parent in resolved_path.parents:
            if parent == resolved_user_dir:
                break
            if parent.is_symlink():
                return jsonify({"error": "symbolic links not allowed"})
            
    except (ValueError, OSError) as e:
        return jsonify({"error": "path resolution failed"})
    
    # MITIGATION: Use atomic file creation pattern to prevent race conditions
    temp_path = None
    try:
        # Create temporary file securely in the same directory
        with tempfile.NamedTemporaryFile(
            mode='w', 
            encoding='utf-8', 
            dir=resolved_user_dir, 
            delete=False, 
            prefix='temp_', 
            suffix='.txt'
        ) as temp_file:
            temp_file.write(text_param)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_path = Path(temp_file.name)
        
        # MITIGATION: Set restrictive file permissions (0600 - owner read/write only)
        temp_path.chmod(0o600)
        
        # MITIGATION: Atomic move operation
        shutil.move(str(temp_path), str(resolved_path))
        
    except Exception as e:
        # Clean up temp file if it exists
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
        return jsonify({"error": "failed to write file"})
    
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
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})

