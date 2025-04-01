import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
# Add rate limiting to prevent brute force attacks
limiter = Limiter(app, key_func=get_remote_address)

@limiter.limit("5 per minute")
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
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
    
    # Add username validation - only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username contains invalid characters"}), 400
    
    # Improved password validation
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    # Access level validation
    try:
        access_level_int = int(access_level)
        if access_level_int < 0 or access_level_int > 3:  # Define valid range
            raise ValueError("Invalid access level range")
    except ValueError:
        return jsonify({"error": "Invalid access level provided"}), 400
    
    # Hash the password before storing it
    hashed_password = generate_password_hash(password)
    
    # Use parameterized query to prevent SQL injection
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    params = (username, hashed_password, access_level_int)

    try:
        query_db(query, params, False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        return jsonify({"error": "could not create user: " + str(err)})

# Adding security headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
