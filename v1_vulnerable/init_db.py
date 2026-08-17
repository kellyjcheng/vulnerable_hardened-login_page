# init_db.py — Version 1 (Vulnerable)
#
# Purpose: create the SQLite database and a `users` table, then seed
# it with at least one test account so app.py has something to log into.
#
# Build steps:
# 1. Import sqlite3.
# 2. Connect to (or create) a local file, e.g. "users.db".
# 3. CREATE TABLE IF NOT EXISTS users with columns:
#       id INTEGER PRIMARY KEY AUTOINCREMENT
#       username TEXT UNIQUE NOT NULL
#       password TEXT NOT NULL
#    # VULN: password column stores plain text — no hash, no salt.
#    # Anyone who reads the DB file (leak, backup, injection) gets every
#    # credential in cleartext.
# 4. Insert one or two demo users directly with plain-text passwords,
#    e.g. ("admin", "admin123"), so there's something to test login
#    and the SQL injection bypass against.
# 5. Commit and close the connection.
#
# Run this once before starting app.py: `python init_db.py`
