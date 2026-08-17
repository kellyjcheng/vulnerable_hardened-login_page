# app.py — Version 1 (Vulnerable)
#
# A deliberately broken Flask login app. Every weakness below is tagged
# # VULN so it's easy to cross-reference against README.md and
# docs/attack_surface_map.md.
#
# ---------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------
# 1. Import Flask, request, redirect, url_for, render_template, session.
# 2. Import sqlite3 for raw DB access.
# 3. Create the Flask app.
# 4. Set app.secret_key to something trivial/hardcoded.
#    # VULN: hardcoded, guessable secret key — anyone who reads the
#    # source (or brute-forces common keys) can forge session cookies.
#
# ---------------------------------------------------------------------
# Route: GET/POST /  or  /login
# ---------------------------------------------------------------------
# - GET: render templates/login.html
# - POST:
#     1. Read username/password straight from request.form — no
#        validation, no length limits, no escaping.
#     2. Build the SQL query by concatenating the raw strings directly
#        into the query text.
#        # VULN: SQL Injection — string concatenation means input like
#        # ' OR '1'='1' -- lets an attacker bypass auth entirely or
#        # dump the table. (See README "Bypass payload" example.)
#     3. Execute the query with sqlite3 and fetch a result.
#     4. No rate limiting or attempt counting of any kind.
#        # VULN: Missing rate limits — unlimited login attempts means
#        # brute-forcing passwords is just a matter of time.
#     5. On a matching row, set a simple session value (e.g.
#        session['username'] = username) and redirect to /dashboard.
#        # VULN: Weak session handling — no signing beyond Flask's
#        # trivial secret_key, no HttpOnly/Secure flags set explicitly,
#        # no session regeneration on login (session fixation risk).
#     6. On no match, re-render login.html with a generic-looking error
#        (or, worse, a DB error) — consider what info you leak here.
#
# ---------------------------------------------------------------------
# Route: GET/POST /register
# ---------------------------------------------------------------------
# - GET: render templates/register.html
# - POST:
#     1. Read new username/password from the form.
#     2. Insert directly into the users table with string concatenation
#        (same injection flaw as login) and the password stored as-is.
#        # VULN: Plain text password storage — no hashing at all.
#     3. Redirect to /login on success.
#
# ---------------------------------------------------------------------
# Route: GET /dashboard
# ---------------------------------------------------------------------
# - Intended to be "logged-in only" but built carelessly:
#     # VULN: Broken access control — if you forget to check
#     # session['username'] before rendering, the dashboard is
#     # reachable by anyone who guesses/knows the URL, logged in or not.
# - Render templates/dashboard.html, maybe showing the username.
#
# ---------------------------------------------------------------------
# Route: GET /logout
# ---------------------------------------------------------------------
# - Clear the session and redirect to /login.
#   (Even this can be done insecurely — e.g. not fully invalidating
#   server-side state — worth comparing against v2 later.)
#
# ---------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------
# if __name__ == "__main__":
#     app.run(debug=True)
#     # VULN: debug=True in anything resembling production exposes the
#     # Werkzeug interactive debugger — remote code execution risk.
