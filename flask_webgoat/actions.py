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

    # Validate filename to prevent directory traversal
    if not re.match("^[A-Za-z0-9._-]+$", filename_param):
        return jsonify({"error": "invalid filename"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    with path.open("w", encoding="utf-8") as open_file:
        # Escaping text_param to prevent command injection
        open_file.write(re.escape(text_param))
    return jsonify({"success": True})



@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    # Validate name to prevent command injection
    if not re.match("^[A-Za-z0-9._-]+$", name):
        return jsonify({"error": "invalid name"})
    # Using shlex to split command into tokens to prevent command injection
    res = subprocess.run(
        shlex.split("ps aux | grep " + name + " | awk '{print $11}'"),
        shell=False,
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
    # Using secure deserialization library
    deserialized = dill.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})

