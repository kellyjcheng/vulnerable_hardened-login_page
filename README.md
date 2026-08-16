# vulnerable_hardened-login_page

A security-focused educational project demonstrating the contrast between a deliberately vulnerable and a properly hardened login system — built with Python, Flask, and SQLite.

This project is not a demonstration of *what to build*. It's a demonstration of *what happens when you don't build it right*, and how to fix it.

---

## Purpose

Every vulnerability in Version 1 is real. These are not contrived edge cases — they are the exact classes of bug that appear in production systems and in CVEs every year. Version 2 is the corrective, applying defence-in-depth principles to address each attack surface systematically.

The codebase is annotated throughout with `# VULN:` and `# FIX:` comments so that each line of code can be read as a security decision, not just an implementation detail.

---

## Project Structure

```
vulnerable_hardened-login_page/
│
├── README.md                   ← You are here
│
├── v1_vulnerable/              ← Deliberately insecure implementation
│   ├── app.py                  ← Flask application (annotated with VULN comments)
│   ├── init_db.py              ← Database initialisation script
│   ├── requirements.txt        ← Minimal dependencies
│   ├── templates/
│   │   ├── login.html
│   │   ├── register.html
│   │   └── dashboard.html
│   └── static/
│       └── style.css
│
├── v2_hardened/                ← Hardened implementation
│   ├── app.py                  ← Flask application (annotated with FIX comments)
│   ├── init_db.py              ← Database initialisation script
│   ├── requirements.txt        ← Includes bcrypt, flask-limiter, flask-session
│   ├── templates/
│   │   ├── login.html
│   │   ├── register.html
│   │   └── dashboard.html
│   └── static/
│       └── style.css
│
└── docs/
    └── attack_surface_map.md   ← Per-vulnerability breakdown with exploit examples
```

---

## Versions at a Glance

### Version 1 — Vulnerable

| Attack Surface | Implementation | Risk |
|---|---|---|
| Password storage | Plaintext in database | Full credential exposure on DB breach |
| Query construction | String concatenation | SQL injection — auth bypass, data dump |
| Login attempts | Unlimited | Brute force / credential stuffing |
| Session handling | Weak, unsigned token | Session fixation / hijacking |

### Version 2 — Hardened

| Attack Surface | Implementation | Defence |
|---|---|---|
| Password storage | bcrypt with per-user salt | Rainbow tables and DB dumps are useless |
| Query construction | Parameterised queries | SQL injection structurally impossible |
| Login attempts | Rate limiting + account lockout | Brute force made computationally infeasible |
| Session handling | HttpOnly + Secure flags, cryptographic token | Token theft mitigated; MITM and XSS hardened |

---

## Key Vulnerabilities Demonstrated

### 1. SQL Injection (v1)
The login query in v1 is built by concatenating user input directly into the SQL string. An attacker supplying `' OR '1'='1` as a username can bypass authentication entirely without knowing any valid credentials. The same technique can be extended to dump the entire user table.

**v1 query:**
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**Payload that bypasses auth:**
```
username: ' OR '1'='1' --
password: anything
```

**v2 fix:** Parameterised queries — the database driver handles escaping; user input is *never* interpreted as SQL syntax.

---

### 2. Plaintext Password Storage (v1)
Passwords in v1 are stored exactly as the user typed them. A single SQL injection, a misconfigured backup, or a database file left in a public S3 bucket exposes every user's password immediately — including reused passwords for other services.

**v2 fix:** bcrypt hashes with a per-user salt. bcrypt is intentionally slow (configurable cost factor). Even with the hash, an attacker cannot reverse it to the plaintext without a full brute-force at ~cost per guess.

---

### 3. No Rate Limiting (v1)
v1 accepts unlimited login attempts with no delay, lockout, or alerting. An attacker can submit thousands of password guesses per second programmatically.

**v2 fix:** `flask-limiter` enforces a request cap per IP. After N consecutive failures, the account is locked for a configurable window. This makes automated credential stuffing and dictionary attacks impractical.

---

### 4. Insecure Session Handling (v1)
v1 issues a session token that is predictable and transmitted without security flags. It can be intercepted over HTTP, stolen by client-side JavaScript (XSS), or fixed by an attacker before login.

**v2 fix:** Sessions are cryptographically signed using Flask's SECRET_KEY via itsdangerous. Cookies are issued with HttpOnly (blocks JS access) and Secure (HTTPS only) flags. The session token is non-deterministic and expires on logout.

---

## How to Run

### Prerequisites
- Python 3.9+
- pip

### Version 1

```bash
cd v1_vulnerable
pip install -r requirements.txt
python init_db.py
python app.py
# → http://127.0.0.1:5000
```

### Version 2

```bash
cd v2_hardened
pip install -r requirements.txt
python init_db.py
python app.py
# → http://127.0.0.1:5000
```

> **Note:** Run only one version at a time, or change the port in app.py (app.run(port=5001)).

---

## Annotated Comment Convention

All security-relevant decisions in the source code are marked with a two-part comment:

```python
# VULN: [attack class] — [why this is dangerous]
# FIX:  [defence applied] — [why this mitigates it]
```

These comments are intentional. The goal is for this codebase to function as a readable security reference, not just a working application.

---

## Concepts Covered (OWASP Alignment)

| OWASP Top 10 Category | Covered In |
|---|---|
| A01 — Broken Access Control | Session fixation, dashboard access without auth (v1) |
| A02 — Cryptographic Failures | Plaintext password storage (v1) |
| A03 — Injection | SQL injection via string concatenation (v1) |
| A07 — Identification and Authentication Failures | No rate limiting, weak sessions (v1) |

---

## Disclaimer

This project is for **educational purposes only**. The vulnerable version (v1_vulnerable) contains intentional security flaws. Do not deploy it to a public-facing server or use it as the basis for any production system.

---

## Author

Kelly — cybersecurity student, CTF competitor, and aspiring network security engineer.
