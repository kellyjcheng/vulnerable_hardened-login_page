"""app.py — Version 2 (Hardened)

Same feature set as v1_vulnerable/app.py (login, register, dashboard,
logout) but each weakness is patched. Every fix is tagged # FIX and
cross-references the matching # VULN in v1_vulnerable/app.py.
"""

import os
import secrets
import sqlite3
import time

import bcrypt
from flask import Flask, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session

app = Flask(__name__)

# FIX: secret key comes from the environment, not a hardcoded literal.
# Falls back to a random key at startup only for local testing — set
# FLASK_SECRET_KEY for anything persistent, since a fallback key
# invalidates all sessions on every restart.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# FIX: server-side session storage instead of a purely client-side
# cookie, plus explicit HttpOnly/Secure/SameSite flags.
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
Session(app)

# FIX: global rate limiting on top of the login-specific limit below,
# so no single endpoint (or client) can be hammered without bound.
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

DB_PATH = "users.db"

# FIX: brute-force lockout tracking, keyed by username. This is an
# in-memory dict for demo purposes only — a real deployment would use
# a shared store (e.g. Redis) so lockouts survive restarts and apply
# across multiple app instances.
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def get_db_connection():
    """Open a connection to the SQLite database for this request.

    Parameters: none.

    Returns:
        sqlite3.Connection: a connection to DB_PATH with row access
        by column name enabled.

    Raises:
        sqlite3.Error: if the database file cannot be opened.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def is_locked_out(username):
    """Check whether a username is currently locked out of login.

    # FIX: brute-force protection — after MAX_ATTEMPTS consecutive
    # failures, further attempts are rejected until LOCKOUT_SECONDS
    # has elapsed since the last failure.

    Parameters:
        username (str): the submitted username to check.

    Returns:
        bool: True if the account is currently locked out, False
        otherwise.

    Raises: none.
    """
    record = FAILED_ATTEMPTS.get(username)
    if not record:
        return False
    count, last_attempt = record
    if count < MAX_ATTEMPTS:
        return False
    return (time.time() - last_attempt) < LOCKOUT_SECONDS


def record_failed_attempt(username):
    """Increment the failed-login counter for a username.

    Parameters:
        username (str): the username that just failed to authenticate.

    Returns: None.

    Raises: none.
    """
    count, _ = FAILED_ATTEMPTS.get(username, (0, 0))
    FAILED_ATTEMPTS[username] = (count + 1, time.time())


def clear_failed_attempts(username):
    """Reset the failed-login counter for a username after success.

    Parameters:
        username (str): the username that just authenticated.

    Returns: None.

    Raises: none.
    """
    FAILED_ATTEMPTS.pop(username, None)


def get_csrf_token():
    """Return the current session's CSRF token, creating one if needed.

    # FIX: CSRF protection — a per-session token is embedded in every
    # state-changing form and verified on submit, so a forged
    # cross-site request without the token is rejected.

    Parameters: none.

    Returns:
        str: a URL-safe random token stored in the session.

    Raises: none.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def verify_csrf_token(submitted_token):
    """Validate a submitted CSRF token against the session's token.

    Parameters:
        submitted_token (str | None): the value of the hidden
        "csrf_token" form field from the incoming request.

    Returns:
        bool: True if the token matches the session's token exactly,
        False otherwise (including when either value is missing).

    Raises: none.
    """
    session_token = session.get("csrf_token")
    return bool(session_token) and secrets.compare_digest(session_token, submitted_token or "")


@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """Render the login form and process login submissions.

    On GET, shows the login page with a fresh CSRF token. On POST,
    verifies the CSRF token, checks for an active lockout, then looks
    up the submitted username and verifies the password with bcrypt.

    # FIX: parameterized query closes the SQL injection hole from v1.
    # FIX: bcrypt.checkpw replaces the plain-text comparison.
    # FIX: session.clear() + repopulation regenerates the session on
    # login, preventing session fixation.
    # FIX: one generic error message for both "no such user" and
    # "wrong password", preventing username enumeration.

    Parameters: none (reads request.form on POST).

    Returns:
        str | werkzeug.wrappers.Response: rendered login.html, or a
        redirect to /dashboard on successful login.

    Raises: none.
    """
    error = None
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            error = "Invalid or expired form submission. Please try again."
            return render_template("login.html", error=error, csrf_token=get_csrf_token())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if is_locked_out(username):
            error = "Too many failed attempts. Please try again in a minute."
            return render_template("login.html", error=error, csrf_token=get_csrf_token())

        conn = get_db_connection()
        # FIX: parameterized query instead of string concatenation.
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            clear_failed_attempts(username)
            # FIX: clear the session before repopulating it so a new
            # session identifier is issued on every successful login.
            session.clear()
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        record_failed_attempt(username)
        error = "Invalid username or password."

    return render_template("login.html", error=error, csrf_token=get_csrf_token())


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    """Render the registration form and create new accounts.

    # FIX: bcrypt hashing — passwords are never stored in plain text.
    # FIX: parameterized INSERT instead of string concatenation.
    # FIX: minimum password length enforced server-side (client-side
    # hints alone are not trustworthy).
    # FIX: duplicate usernames are handled gracefully instead of
    # leaking a raw database error to the user.

    Parameters: none (reads request.form on POST).

    Returns:
        str | werkzeug.wrappers.Response: rendered register.html, or
        a redirect to /login on successful registration.

    Raises: none.
    """
    error = None
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            error = "Invalid or expired form submission. Please try again."
            return render_template("register.html", error=error, csrf_token=get_csrf_token())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            conn = get_db_connection()
            try:
                # FIX: parameterized query instead of string concatenation.
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                conn.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            finally:
                conn.close()

    return render_template("register.html", error=error, csrf_token=get_csrf_token())


@app.route("/dashboard")
def dashboard():
    """Render the post-login dashboard page.

    # FIX: explicit access-control check — unauthenticated requests
    # are redirected to /login instead of rendering the page, closing
    # the broken-access-control hole from v1.

    Parameters: none.

    Returns:
        str | werkzeug.wrappers.Response: rendered dashboard.html for
        a logged-in user, or a redirect to /login otherwise.

    Raises: none.
    """
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    """Clear the current session and return to the login page.

    Parameters: none.

    Returns:
        werkzeug.wrappers.Response: redirect to /login.

    Raises: none.
    """
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # FIX: debug mode is off, so the interactive Werkzeug debugger
    # (a remote code execution risk if reachable) is never exposed.
    app.run(debug=False)
