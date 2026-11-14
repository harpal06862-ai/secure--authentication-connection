"""
Secure Authentication System
Stack: Flask + PyJWT + bcrypt + PostgreSQL

Flow
  register  -> password hashed with bcrypt, stored in PostgreSQL
  login     -> bcrypt verify -> short-lived JWT access token (JSON)
               + long-lived refresh token (HttpOnly cookie, stored hashed in DB)
  /api/me   -> protected route, needs "Authorization: Bearer <access token>"
  refresh   -> rotates refresh token; reuse of an old one revokes all sessions
  logout    -> revokes the refresh token (session ends server-side)
"""
import hashlib
import os
import re
import secrets
import datetime as dt
from contextlib import contextmanager
from functools import wraps

import bcrypt
import click
import jwt
import psycopg2
from dotenv import load_dotenv
from flask import Flask, g, jsonify, make_response, render_template, request
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool

load_dotenv()

# ---------------------------------------------------------------- config
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]  # long random string, never commit it
JWT_ALGORITHM = "HS256"
ACCESS_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"  # true behind HTTPS
MAX_FAILED = 5
LOCK_MINUTES = 15

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# a throwaway hash so login takes the same time whether or not the user exists
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())

app = Flask(__name__)
pool = SimpleConnectionPool(1, 10, DATABASE_URL, cursor_factory=RealDictCursor)


# ---------------------------------------------------------------- database
@contextmanager
def db():
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


@app.cli.command("init-db")
def init_db():
    """Create tables:  flask --app app init-db"""
    with open(os.path.join(os.path.dirname(__file__), "schema.sql")) as f:
        sql = f.read()
    with db() as cur:
        cur.execute(sql)
    click.echo("Database ready.")


# ---------------------------------------------------------------- helpers
def now():
    return dt.datetime.now(dt.timezone.utc)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def validate_password(pw: str):
    """Return an error message, or None if the password is acceptable."""
    if len(pw.encode()) > 72:  # bcrypt ignores everything past 72 bytes
        return "Password must be at most 72 bytes."
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)):
        return "Password needs a lowercase letter, an uppercase letter and a digit."
    return None


def make_access_token(user_id: int) -> str:
    t = now()
    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": secrets.token_hex(8),
        "iat": t,
        "exp": t + dt.timedelta(minutes=ACCESS_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def issue_refresh_token(cur, user_id: int) -> str:
    raw = secrets.token_urlsafe(48)
    cur.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent) "
        "VALUES (%s, %s, %s, %s)",
        (user_id, sha256(raw), now() + dt.timedelta(days=REFRESH_DAYS),
         (request.headers.get("User-Agent") or "")[:200]),
    )
    return raw


def token_response(user, raw_refresh, status=200):
    resp = make_response(jsonify({
        "access_token": make_access_token(user["id"]),
        "expires_in": ACCESS_MINUTES * 60,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"]},
    }), status)
    resp.set_cookie(
        "refresh_token", raw_refresh,
        max_age=REFRESH_DAYS * 86400, httponly=True,
        secure=COOKIE_SECURE, samesite="Strict", path="/api/auth",
    )
    return resp


def error(message, status):
    return jsonify({"error": message}), status


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return error("Missing bearer token.", 401)
        try:
            claims = jwt.decode(
                header[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM],  # fixed algorithm list
                options={"require": ["exp", "iat", "sub"]},
            )
            if claims.get("type") != "access":
                return error("Wrong token type.", 401)
        except jwt.ExpiredSignatureError:
            return error("Token expired.", 401)
        except jwt.InvalidTokenError:
            return error("Invalid token.", 401)
        g.user_id = int(claims["sub"])
        return fn(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )
    return resp


# ---------------------------------------------------------------- routes
@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not (3 <= len(username) <= 30) or not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        return error("Username: 3-30 characters, letters, digits, _ . - only.", 400)
    if not EMAIL_RE.match(email) or len(email) > 254:
        return error("Enter a valid email address.", 400)
    problem = validate_password(password)
    if problem:
        return error(problem, 400)

    try:
        with db() as cur:
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) "
                "RETURNING id",
                (username, email, hash_password(password)),
            )
            user_id = cur.fetchone()["id"]
    except psycopg2.errors.UniqueViolation:
        return error("That username or email is already registered.", 409)

    return jsonify({"message": "Account created. You can log in now.", "id": user_id}), 201


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    generic = "Incorrect email or password."  # never reveal which one is wrong

    with db() as cur:
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user is None:
            check_password(password, DUMMY_HASH.decode())  # equalise timing
            return error(generic, 401)

        if user["locked_until"] and user["locked_until"] > now():
            return error("Too many failed attempts. Try again in a few minutes.", 429)

        if not check_password(password, user["password_hash"]):
            failed = user["failed_attempts"] + 1
            locked = now() + dt.timedelta(minutes=LOCK_MINUTES) if failed >= MAX_FAILED else None
            cur.execute(
                "UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s",
                (0 if locked else failed, locked, user["id"]),
            )
            return error(generic, 401)

        cur.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s",
                    (user["id"],))
        raw_refresh = issue_refresh_token(cur, user["id"])

    return token_response(user, raw_refresh)


@app.post("/api/auth/refresh")
def refresh():
    raw = request.cookies.get("refresh_token")
    if not raw:
        return error("No session.", 401)

    with db() as cur:
        cur.execute("SELECT * FROM refresh_tokens WHERE token_hash = %s", (sha256(raw),))
        row = cur.fetchone()
        if row is None:
            return error("Invalid session.", 401)

        if row["revoked"]:
            # an old token was replayed -> assume theft, kill every session of this user
            cur.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = %s",
                        (row["user_id"],))
            return error("Session no longer valid. Please log in again.", 401)

        if row["expires_at"] < now():
            return error("Session expired.", 401)

        cur.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE id = %s", (row["id"],))
        cur.execute("SELECT id, username, email FROM users WHERE id = %s", (row["user_id"],))
        user = cur.fetchone()
        new_refresh = issue_refresh_token(cur, user["id"])  # rotation

    return token_response(user, new_refresh)


@app.post("/api/auth/logout")
def logout():
    raw = request.cookies.get("refresh_token")
    if raw:
        with db() as cur:
            cur.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = %s",
                        (sha256(raw),))
    resp = make_response(jsonify({"message": "Logged out."}))
    resp.delete_cookie("refresh_token", path="/api/auth")
    return resp


@app.post("/api/auth/logout-all")
@login_required
def logout_all():
    with db() as cur:
        cur.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = %s", (g.user_id,))
    resp = make_response(jsonify({"message": "Logged out of every device."}))
    resp.delete_cookie("refresh_token", path="/api/auth")
    return resp


@app.get("/api/me")
@login_required
def me():
    with db() as cur:
        cur.execute("SELECT id, username, email, created_at FROM users WHERE id = %s",
                    (g.user_id,))
        user = cur.fetchone()
        cur.execute(
            "SELECT COUNT(*) AS n FROM refresh_tokens "
            "WHERE user_id = %s AND NOT revoked AND expires_at > now()", (g.user_id,))
        sessions = cur.fetchone()["n"]
    if user is None:
        return error("User not found.", 404)
    user["created_at"] = user["created_at"].isoformat()
    user["active_sessions"] = sessions
    return jsonify(user)


if __name__ == "__main__":
    app.run(debug=False, port=5000)
