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
    encoded_data = request.form.get('data')
    if not encoded_data:
        return jsonify({"error": "Missing required data parameter"})
    
    # Implement size limits to prevent DoS attacks
    MAX_DATA_SIZE = 10240  # 10KB limit
    if len(encoded_data) > MAX_DATA_SIZE:
        return jsonify({"error": "Data payload too large"})
        
    try:
        # Using JSON instead of pickle for secure deserialization
        decoded = base64.urlsafe_b64decode(encoded_data)
        
        # Add data integrity check with HMAC validation
        if b'.' not in decoded:
            return jsonify({"error": "Invalid data format: missing signature"})
            
        serialized, signature = decoded.split(b'.', 1)
        expected_sig = hmac.digest(request.secret_key.encode(), serialized, 'sha256')
        if not hmac.compare_digest(signature, expected_sig):
            return jsonify({"error": "Invalid signature"})
            
        data = serialized.decode('utf-8')
        deserialized = json.loads(data)
        
        # Implement type safety
        if not isinstance(deserialized, dict):
            return jsonify({"error": "Invalid data structure: expected object"})
        
        # Add schema validation
        schema = {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "metadata": {"type": "object"}
            },
            "required": ["description"]
        }
        jsonschema.validate(instance=deserialized, schema=schema)
        
        # Use contextual output encoding for the response
        safe_description = escape(json.dumps(deserialized))
        return jsonify({"success": True, "description": safe_description})
    except jsonschema.exceptions.ValidationError as e:
        return jsonify({"error": f"Schema validation failed: {str(e)}"})
    except Exception as e:
        return jsonify({"error": f"Invalid data format: {str(e)}"})

def create_signed_data(data):
    """Helper function to create signed data for secure deserialization"""
    serialized = json.dumps(data)
    signature = hmac.digest(request.secret_key.encode(), serialized.encode(), 'sha256')
    return base64.urlsafe_b64encode(serialized.encode() + b'.' + signature)
