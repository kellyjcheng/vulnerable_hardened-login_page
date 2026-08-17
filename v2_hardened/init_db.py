# init_db.py — Version 2 (Hardened)
#
# Same job as v1's init_db.py — create the SQLite DB and seed a test
# account — but the password column now holds a bcrypt hash, never
# plain text.
#
# Build steps:
# 1. Import sqlite3 and bcrypt.
# 2. Connect to (or create) "users.db" (can reuse the same filename as
#    v1 as long as the two apps aren't pointed at each other's file).
# 3. CREATE TABLE IF NOT EXISTS users with columns:
#       id INTEGER PRIMARY KEY AUTOINCREMENT
#       username TEXT UNIQUE NOT NULL
#       password_hash TEXT NOT NULL
#    # FIX: column is explicitly named password_hash (not "password")
#    # as a reminder that raw passwords are never stored or compared.
# 4. For each seed user, hash the plaintext with
#    bcrypt.hashpw(password.encode(), bcrypt.gensalt()) before insert.
#    # FIX: bcrypt generates a unique salt per password automatically,
#    # so two users with the same password get different hashes, and
#    # the hash work factor makes bulk offline cracking slow.
# 5. Use a parameterized INSERT ("INSERT INTO users VALUES (?, ?)",
#    (username, hash)) rather than string concatenation.
#    # FIX: parameterized queries — same principle applied in app.py.
# 6. Commit and close.
