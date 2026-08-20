"""init_db.py — Version 1 (Vulnerable)

Creates the SQLite database used by app.py and seeds it with a demo
account. Run this once before starting the app: `python init_db.py`
"""

import sqlite3

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

    # VULN: the password column stores plain text — no hash, no salt.
    # Anyone who reads this database file directly (leak, backup,
    # SQL injection) gets every credential in cleartext.

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
            password TEXT NOT NULL
        )
        """
    )
    conn.commit()


def seed_users(conn):
    """Insert demo accounts with plain-text passwords for testing.

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
        try:
            # VULN: plain-text password inserted as-is, no hashing.
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
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
