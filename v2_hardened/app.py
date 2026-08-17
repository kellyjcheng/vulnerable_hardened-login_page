# app.py — Version 2 (Hardened)
#
# Same feature set as v1_vulnerable/app.py (login, register, dashboard,
# logout) but each weakness is patched. Every fix is tagged # FIX and
# cross-references the matching # VULN in v1 for easy comparison.
#
# ---------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------
# 1. Import Flask, request, redirect, url_for, render_template, session.
# 2. Import sqlite3, bcrypt.
# 3. Import Limiter (flask-limiter) and Session (flask-session).
# 4. Create the Flask app.
# 5. Load app.secret_key from an environment variable or a config file
#    that is NOT committed to git — never hardcode it.
#    # FIX: unpredictable, externally-supplied secret key — cookies
#    # signed with it can't be forged without the key.
# 6. Configure flask-session (e.g. filesystem or Redis-backed) and set:
#      SESSION_COOKIE_HTTPONLY = True
#      SESSION_COOKIE_SECURE = True     (requires HTTPS in production)
#      SESSION_COOKIE_SAMESITE = "Lax"  (or "Strict")
#    # FIX: HttpOnly blocks JS/XSS access to the cookie; Secure blocks
#    # transmission over plain HTTP; SameSite mitigates CSRF.
# 7. Initialize Limiter, keyed by remote address, with a sane default
#    (e.g. "200 per day, 50 per hour") applied globally.
#
# ---------------------------------------------------------------------
# Route: GET/POST /  or  /login
# ---------------------------------------------------------------------
# - GET: render templates/login.html
# - POST:
#     1. Apply a stricter @limiter.limit(...) to this route specifically
#        (e.g. "5 per minute") plus your own failed-attempt counter per
#        username/IP that triggers a temporary lockout.
#        # FIX: rate limiting + lockout — throttles brute-force and
#        # credential-stuffing attempts instead of allowing unlimited
#        # tries.
#     2. Read username/password from request.form, validate presence
#        and reasonable length before touching the DB.
#     3. Look up the user with a PARAMETERIZED query:
#        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
#        # FIX: parameterized queries — user input is always treated as
#        # data, never as part of the SQL statement, closing the
#        # injection hole from v1.
#     4. If a row is found, verify with
#        bcrypt.checkpw(password.encode(), row["password_hash"]) rather
#        than a plaintext comparison.
#     5. On success: call session.clear() then re-set session data
#        (regenerates the session identifier).
#        # FIX: session regeneration on login prevents session fixation
#        # — an attacker can't pre-set a session ID and hijack it once
#        # the victim logs in.
#     6. On failure: show one generic error message regardless of
#        whether the username existed or the password was wrong.
#        # FIX: no user enumeration via differing error messages.
#
# ---------------------------------------------------------------------
# Route: GET/POST /register
# ---------------------------------------------------------------------
# - GET: render templates/register.html
# - POST:
#     1. Validate username/password (non-empty, minimum length/
#        complexity rules of your choosing).
#     2. Hash the password with bcrypt before storing:
#        bcrypt.hashpw(password.encode(), bcrypt.gensalt())
#        # FIX: passwords are never stored in plain text.
#     3. Insert with a parameterized query.
#     4. Handle the UNIQUE constraint failure (duplicate username)
#        gracefully instead of leaking a raw DB error to the user.
#
# ---------------------------------------------------------------------
# Route: GET /dashboard
# ---------------------------------------------------------------------
# - First line of the view function checks session for a logged-in
#   user; if absent, redirect to /login immediately.
#   # FIX: explicit access control check — fixes v1's broken access
#   # control where the page rendered for anyone who requested it.
# - Consider a small @login_required decorator to enforce this
#   consistently on every protected route as the app grows.
#
# ---------------------------------------------------------------------
# Route: GET /logout
# ---------------------------------------------------------------------
# - session.clear() (not just deleting one key) so no residual session
#   state survives, then redirect to /login.
#
# ---------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------
# if __name__ == "__main__":
#     app.run(debug=False)
#     # FIX: debug mode off — no interactive debugger/RCE exposure.
#     # For local testing over HTTP you may need SESSION_COOKIE_SECURE
#     # temporarily False; note that trade-off, don't ship it that way.
