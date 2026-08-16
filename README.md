# vulnerable_hardened-login_page

A side-by-side comparison of a broken authentication system versus a secure one, built with Python, Flask, and SQLite. 

This project isn't a blueprint for how to build a login page — it's a breakdown of common security mistakes, why they break in the real world, and how to write code that actually holds up.

---

## What This Is

Version 1 is packed with real bugs — the kind that show up constantly in actual web apps and leak real credentials. Version 2 cleans up those flaws with practical fixes you'd actually use in production.

Every security decision in the codebase is tagged with `# VULN:` or `# FIX:` comments so you can follow along directly in the code.

---

## Project Structure

```
vulnerable_hardened-login_page/
│
├── README.md                   ← You are here
│
├── v1_vulnerable/              ← Insecure implementation
│   ├── app.py                  ← Flask app (tagged with # VULN)
│   ├── init_db.py              ← DB setup
│   ├── requirements.txt        ← Minimal dependencies
│   ├── templates/
│   │   ├── login.html
│   │   ├── register.html
│   │   └── dashboard.html
│   └── static/
│       └── style.css
│
├── v2_hardened/                ← Patched implementation
│   ├── app.py                  ← Flask app (tagged with # FIX)
│   ├── init_db.py              ← DB setup
│   ├── requirements.txt        ← Includes bcrypt, flask-limiter, flask-session
│   ├── templates/
│   │   ├── login.html
│   │   ├── register.html
│   │   └── dashboard.html
│   └── static/
│       └── style.css
│
└── docs/
    └── attack_surface_map.md   ← Exploit breakdown and walkthroughs
```

---

## Quick Comparison

### Version 1 — Vulnerable

| Feature | Implementation | Impact |
|---|---|---|
| Passwords | Stored in plain text | A single database breach leaks every user password |
| Database Queries | Raw string concatenation | SQL injection allows auth bypass and full database dumps |
| Login Security | Unlimited password attempts | Open to simple brute-force attacks |
| Sessions | Unsigned, predictable tokens | Easy to hijack or trick users into fixed sessions |

### Version 2 — Hardened

| Feature | Implementation | Fix |
|---|---|---|
| Passwords | `bcrypt` with individual salts | Hashes can't be reversed or looked up in pre-computed tables |
| Database Queries | Parameterized queries | User input is safely handled so SQL injection won't work |
| Login Security | Rate limiting + lockout rules | Slows down automated login spam to a crawl |
| Sessions | `HttpOnly` + `Secure` signed cookies | Blocks JavaScript access and stops token interception |

---

## The Flaws & The Fixes

### 1. SQL Injection (v1)
In v1, user input gets stuck directly inside the SQL string. Entering `' OR '1'='1` as the username lets anyone log in without a password or dump the entire user database.

**v1 code:**
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**Bypass payload:**
```
username: ' OR '1'='1' --
password: anything
```

**v2 fix:** Parameterized queries. The database handles user input safely as raw data, not executable code.

---

### 2. Plain Text Passwords (v1)
v1 stores passwords raw. If the database leaks through a bad backup, open bucket, or SQL injection, every password is right there in the clear.

**v2 fix:** `bcrypt` hashing with unique salts. `bcrypt` adds an artificial delay to password checks, making bulk offline guessing painful and slow.

---

### 3. Missing Rate Limits (v1)
v1 lets anyone guess passwords as fast as their internet connection allows.

**v2 fix:** `flask-limiter` sets a hard cap on attempts per IP address and temporarily locks accounts after too many failed tries.

---

### 4. Weak Session Cookies (v1)
v1 uses simple session tokens without security flags. They can be stolen via script injection (XSS), sniffed over plain HTTP, or set by an attacker before the user even logs in.

**v2 fix:** Cryptographically signed session tokens using Flask's `SECRET_KEY`. Cookies use `HttpOnly` (stops JavaScript from reading them) and `Secure` (requires HTTPS).

---

## How to Run

### Requirements
- Python 3.9+
- `pip`

### Running Version 1

```bash
cd v1_vulnerable
pip install -r requirements.txt
python init_db.py
python app.py
# Open http://127.0.0.1:5000
```

### Running Version 2

```bash
cd v2_hardened
pip install -r requirements.txt
python init_db.py
python app.py
# Open http://127.0.0.1:5000
```

> **Note:** Run one version at a time, or change the port inside `app.py` (`app.run(port=5001)`).

---

## Code Annotations

All security choices in the code are tagged with comments:

```python
# VULN: [issue] — [why it breaks]
# FIX:  [solution] — [how it fixes it]
```

---

## OWASP Top 10 Mapping

| OWASP Category | Where it shows up in v1 |
|---|---|
| A01 — Broken Access Control | Unauthenticated dashboard access & session fixation |
| A02 — Cryptographic Failures | Storing passwords in plain text |
| A03 — Injection | SQL injection via string concatenation |
| A07 — Identification & Authentication Failures | No brute-force protection & weak cookies |

---

## Disclaimer

This repo is strictly for **learning and testing**. Version 1 is broken on purpose — don't host it online or reuse the vulnerable code in real projects.

---

## Author

Kelly — CS Student at UW, focus in Cybersecurity, aspiring penetration tester with specialization in AI security.
