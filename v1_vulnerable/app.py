"""app.py — Version 1 (Vulnerable)

A deliberately broken Flask login app for learning purposes only.
Every weakness below is tagged # VULN and cross-referenced against
README.md and docs/attack_surface_map.md. Do not host this online or
reuse this code in a real project.
"""

import sqlite3

from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)

# VULN: hardcoded, guessable secret key — anyone who reads the source
# (or brute-forces common keys) can forge session cookies signed with it.
app.secret_key = "dev"

DB_PATH = "users.db"


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


@app.route("/", methods=["GET", "POST"])
def login():
    """Render the login form and process login submissions.

    On GET, shows the login page. On POST, looks up the submitted
    username/password against the users table and starts a session
    on success.

    # VULN: SQL Injection — the query is built with raw string
    # concatenation, so input like `' OR '1'='1' --` as the username
    # bypasses authentication entirely or can be used to dump data.
    #
    # VULN: Missing rate limits — there is no cap on attempts, so
    # brute-forcing passwords is only a matter of time.
    #
    # VULN: Weak session handling — session data is signed only with
    # the trivial hardcoded secret_key above, and the session is not
    # regenerated on login (session fixation risk).

    Parameters: none (reads request.form on POST).

    Returns:
        str | werkzeug.wrappers.Response: rendered login.html, or a
        redirect to /dashboard on successful login.

    Raises: none (database errors propagate as unhandled exceptions,
        which is itself a vulnerability — see attack_surface_map.md).
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db_connection()
        # VULN: string concatenation instead of a parameterized query.
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        cursor = conn.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            # VULN: no session.clear()/regeneration before setting new
            # session data — vulnerable to session fixation.
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Render the registration form and create new accounts.

    # VULN: plain-text password storage — no hashing at all.
    # VULN: same SQL string concatenation as login().
    # VULN: no password policy — any non-empty string is accepted.

    Parameters: none (reads request.form on POST).

    Returns:
        str | werkzeug.wrappers.Response: rendered register.html, or
        a redirect to /login on successful registration.

    Raises: none (a duplicate username raises sqlite3.IntegrityError,
        which is left unhandled here on purpose).
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db_connection()
        # VULN: string concatenation instead of a parameterized query.
        query = (
            "INSERT INTO users (username, password) VALUES ('"
            + username
            + "', '"
            + password
            + "')"
        )
        conn.execute(query)
        conn.commit()
        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html", error=error)


@app.route("/dashboard")
def dashboard():
    """Render the post-login dashboard page.

    # VULN: Broken access control — there is no check that a user is
    # actually logged in before rendering this page, so anyone who
    # requests /dashboard directly sees it, session or not.

    Parameters: none.

    Returns:
        str: rendered dashboard.html, using the session username if
        present or a generic fallback if not.

    Raises: none.
    """
    username = session.get("username", "guest")
    return render_template("dashboard.html", username=username)


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
    # VULN: debug=True exposes the Werkzeug interactive debugger,
    # which allows remote code execution if reachable by an attacker.
    app.run(debug=True)
