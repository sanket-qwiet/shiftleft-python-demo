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

    # Check for suspicious path patterns before processing
    if ".." in filename_param or "//" in filename_param or "\\" in filename_param:
        return jsonify({"error": "suspicious path pattern detected"})

    # Validate file extension against whitelist
    ALLOWED_EXTENSIONS = {'txt', 'log', 'md'}
    ext = filename_param.rsplit('.', 1)[1].lower() if '.' in filename_param else ''
    if ext and ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "file extension not allowed"})

    # Use secure_filename from werkzeug to sanitize the filename
    safe_base_filename = secure_filename(filename_param)
    if not safe_base_filename:
        return jsonify({"error": "invalid filename after sanitization"})
    
    # Generate UUID-based filename for additional security
    uuid_filename = f"{uuid.uuid4().hex}_{safe_base_filename}"
    if not ext:
        uuid_filename += ".txt"  # Default extension if none provided

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir(parents=True)

    # Create path object correctly using Path.joinpath
    path = user_dir_path.joinpath(uuid_filename)
    
    # Verify the final path is within the intended directory using is_relative_to
    final_path = path.resolve()
    if not final_path.is_relative_to(user_dir_path.resolve()):
        return jsonify({"error": "path traversal detected"})
    
    # Basic content validation - limit size and check for potentially malicious content
    if len(text_param) > 10000:  # Limit file size
        return jsonify({"error": "text content too large"})
    
    # Check for potentially malicious script content
    if "<script" in text_param.lower() or "javascript:" in text_param.lower():
        return jsonify({"error": "potentially malicious content detected"})
        
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    
    # Return response with security header
    response = jsonify({"success": True, "filename": uuid_filename})
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

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
