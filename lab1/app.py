import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "app.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-secret-in-production")  # nosec B105
JWT_ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 30

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )"""
    )
    exists = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if exists is None:
        password = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
        db.execute(
            "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
            ("admin", bcrypt.hashpw(password.encode(), bcrypt.gensalt()), "Administrator", "admin"),
        )
    db.commit()


def token_required(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Bearer token is required"), 401
        token = header[7:].strip()
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify(error="Invalid or expired token"), 401
        g.current_user = payload
        return handler(*args, **kwargs)

    return wrapper


@app.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password are required"), 400
    row = get_db().execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not bcrypt.checkpw(password.encode(), row["password_hash"]):
        return jsonify(error="Invalid credentials"), 401
    token = jwt.encode(
        {"sub": row["id"], "username": row["username"], "role": row["role"],
         "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES)},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )
    return jsonify(access_token=token, token_type="Bearer", expires_in=TOKEN_TTL_MINUTES * 60)


@app.get("/api/data")
@token_required
def users():
    rows = get_db().execute("SELECT id, username, display_name, role FROM users ORDER BY id").fetchall()
    return jsonify(data=[{**dict(row), "username": str(escape(row["username"])),
                          "display_name": str(escape(row["display_name"])),
                          "role": str(escape(row["role"]))} for row in rows])


@app.put("/api/users/me/password")
@token_required
def change_password():
    body = request.get_json(silent=True) or {}
    current = body.get("current_password")
    new = body.get("new_password")
    if not isinstance(current, str) or not isinstance(new, str) or len(new) < 8:
        return jsonify(error="current_password and a new password of at least 8 characters are required"), 400
    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.current_user["sub"],)).fetchone()
    if row is None or not bcrypt.checkpw(current.encode(), row["password_hash"]):
        return jsonify(error="Current password is incorrect"), 403
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt())
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, g.current_user["sub"]))
    db.commit()
    return jsonify(message="Password changed successfully")


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
