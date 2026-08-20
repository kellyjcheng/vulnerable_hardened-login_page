"""init_db.py — Version 2 (Hardened)

Creates the SQLite database used by app.py and seeds it with a demo
account, storing a bcrypt hash instead of a plain-text password.
Run this once before starting the app: `python init_db.py`
"""

import sqlite3

import bcrypt

DB_PATH = "users.db"


def create_connection():
    """Open a connection to the local SQLite database file.

    Parameters: none.

    Returns:
        sqlite3.Connection: a connection to DB_PATH, creating the file
        if it does not already exist.

    Raises:
        sqlite3.Error: if the underlying SQLite library fails to open
        or create the database file (e.g. permissions issue).
    """
    return sqlite3.connect(DB_PATH)


def init_db(conn):
    """Create the users table if it does not already exist.

    # FIX: the column is named password_hash (not "password") as a
    # reminder that raw passwords are never stored or compared here.

    Parameters:
        conn (sqlite3.Connection): open connection to the database.

    Returns: None.

    Raises:
        sqlite3.Error: if the CREATE TABLE statement fails.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()


def seed_users(conn):
    """Insert demo accounts with bcrypt-hashed passwords for testing.

    # FIX: bcrypt.gensalt() generates a unique salt per password, so
    # identical passwords across users produce different hashes, and
    # bcrypt's work factor makes bulk offline cracking slow.

    Parameters:
        conn (sqlite3.Connection): open connection to the database.

    Returns: None.

    Raises:
        sqlite3.IntegrityError: if a seed username already exists
        (the UNIQUE constraint on username is violated). Caught here
        so re-running this script is safe.
    """
    demo_users = [
        ("admin", "admin123"),
        ("alice", "password1"),
    ]
    for username, password in demo_users:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            # FIX: parameterized query — user input is always bound as
            # data, never concatenated into the SQL text.
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()


if __name__ == "__main__":
    connection = create_connection()
    init_db(connection)
    seed_users(connection)
    connection.close()
    print(f"Initialized {DB_PATH} with demo users (admin/admin123, alice/password1).")
