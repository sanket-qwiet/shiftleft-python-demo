import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    # Get form data
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    
    if username is None or password is None or access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    # Input validation to prevent malicious characters
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username contains invalid characters"}), 400
    
    # Enforce maximum input length restrictions
    if len(username) > 50 or len(password) > 100:
        return jsonify({"error": "Username or password exceeds maximum length"}), 400
    
    # Additional input sanitization
    username = bleach.clean(username, strip=True)
    
    # Hash the password instead of storing plaintext
    hashed_password = generate_password_hash(password)
    
    try:
        # Use SQLAlchemy for prepared statements
        engine = create_engine('sqlite:///instance/db.sqlite')
        with engine.connect() as conn:
            # Define allowed queries (query whitelisting)
            allowed_queries = {
                "insert_user": "INSERT INTO user (username, password, access_level) VALUES (:username, :password, :access_level)"
            }
            
            # Use the whitelisted query
            stmt = text(allowed_queries["insert_user"])
            
            # Execute using prepared statement
            conn.execute(stmt, {"username": username, "password": hashed_password, "access_level": int(access_level)})
            conn.commit()
            
        return jsonify({"success": True})
    except Exception as err:
        # Proper error handling without exposing SQL error details
        return jsonify({"error": "Could not create user due to database error"}), 500

