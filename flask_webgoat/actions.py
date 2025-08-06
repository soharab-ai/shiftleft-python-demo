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
    # Validate input - allow only alphanumeric and basic characters
    if name and re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
        # Use list form of subprocess to avoid shell injection
        res = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True
        )
        # Filter results in Python rather than using shell
        filtered_lines = []
        if res.stdout:
            for line in res.stdout.splitlines():
                if name in line:
                    parts = line.split()
                    if len(parts) >= 11:
                        filtered_lines.append(parts[10])  # Get command name (position 11)
        
        # Check if a redirect URL was requested
        redirect_url = request.args.get('redirect_to')
        if redirect_url:
            # Validate redirect URL to prevent open redirect vulnerabilities
            allowed_domains = ['example.com', 'trusted-domain.com', 'internal.company.net']
            parsed_url = urllib.parse.urlparse(redirect_url)
            
            # Only allow relative URLs or URLs to trusted domains
            if not parsed_url.netloc or any(parsed_url.netloc.endswith(domain) for domain in allowed_domains):
                return redirect(redirect_url)
            # Fallback to safe location if redirect URL is not trusted
            return redirect(url_for('index'))
            
        return jsonify(filtered_lines)
    else:
        return jsonify({"error": "Invalid input"}), 400

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
