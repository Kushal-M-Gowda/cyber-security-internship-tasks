# Cyber Security Internship Tasks

Tasks completed as part of the IncodeVision Cyber Security Internship. Each script is a standalone Python program demonstrating a core security concept.

## Task 01 – Basic Vulnerability Scanner
`task_01_vulnerability_scanner.py`

Scans a target website for:
- HTTPS usage
- Common security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy)
- Open common ports (FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, MySQL)
- Server information disclosure

**Run:** `python task_01_vulnerability_scanner.py`

## Task 02 – Password Strength Checker
`password_strength_checker.py`

Checks a password against 5 criteria — minimum length (8+ chars), uppercase, lowercase, digit, and special character — then scores it out of 5 and classifies it as **Weak**, **Medium**, or **Strong**. Prints a pass/fail breakdown for each check plus specific improvement suggestions for any missing criteria.

**Run:** `python password_strength_checker.py`

## Task 03 – Secure Login System with Attack Prevention
`task_03_secure_login_system.py`

Implements:
- User registration with password strength validation
- Password hashing using PBKDF2-HMAC (SHA-256, 100,000 iterations) with unique salts
- Secure login with constant-time hash comparison
- Failed login attempt tracking
- Temporary account lockout after repeated failures (3 attempts → 30-second lockout)

**Run:** `python task_03_secure_login_system.py`

## Task 04 – Phishing Detection System (URL & Email Analysis)
`phishing_detection_system.py`

Analyzes a URL or a block of email text for common phishing indicators and assigns a risk score, classifying the result as **Safe** or **Suspicious**.

Detects:
- Missing HTTPS
- Use of link-shortening services (bit.ly, tinyurl, etc.)
- Raw IP addresses used as domains
- Domains with multiple hyphens or unusually long names
- Lookalike domains mimicking trusted brands (PayPal, Google, Amazon, etc.)
- `@` symbols in URLs used to obscure the real destination
- Suspicious keywords/phrases in email text ("verify your account", "urgent action required", etc.)
- Excessive capital letters (urgency tactic)

**Run:** `python phishing_detection_system.py`

## Tech Stack
- Python 3
- Standard library only (`hashlib`, `secrets`, `socket`, `urllib`, `re`, `time`)

## Author
Kushal M Gowda
