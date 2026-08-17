<!--
  attack_surface_map.md — Exploit breakdown and walkthroughs

  Once v1_vulnerable is built and running, document each exploit here
  as you personally test it. Suggested structure per vulnerability:

  ## 1. SQL Injection — Auth Bypass
  - Endpoint: POST /
  - Payload used (username / password fields)
  - What request you sent (curl or browser form) and what response
    you got back
  - What it proves (e.g. logged in as admin without a password)
  - How v2_hardened blocks it (parameterized queries) — confirm by
    trying the same payload there and showing it fails

  ## 2. SQL Injection — Data Exfiltration
  - Payload(s) used to enumerate/dump table contents (e.g. UNION-based)
  - What data was recoverable

  ## 3. Plain Text Password Exposure
  - Show the users.db contents directly (e.g. via sqlite3 CLI) to
    demonstrate passwords are readable in the raw database file
  - Compare against v2_hardened's users.db showing bcrypt hashes

  ## 4. Brute Force / No Rate Limiting
  - Describe or script a simple loop of login attempts against v1
  - Note how many attempts succeeded before you stopped, and that v2's
    flask-limiter + lockout rejects the same script after N tries

  ## 5. Session Weaknesses
  - Inspect the session cookie in browser dev tools for both versions
  - Note presence/absence of HttpOnly, Secure, SameSite flags
  - Describe a session fixation or hijacking scenario against v1 and
    why v2's session regeneration + signed cookies prevent it

  ## 6. Broken Access Control
  - Show /dashboard reachable pre-login in v1 vs. redirecting to
    /login in v2

  Keep this as a running lab notebook — screenshots, request/response
  snippets, and your own notes on what surprised you are more valuable
  here than polished prose.
-->
