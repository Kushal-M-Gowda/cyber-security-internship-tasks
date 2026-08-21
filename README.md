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

Evaluates password strength based on length and character variety.

## Task 03 – Secure Login System with Attack Prevention
`task_03_secure_login_system.py`

Implements:
- User registration with password strength validation
- Password hashing using PBKDF2-HMAC (SHA-256, 100,000 iterations) with unique salts
- Secure login with constant-time hash comparison
- Failed login attempt tracking
- Temporary account lockout after repeated failures (3 attempts → 30-second lockout)

**Run:** `python task_03_secure_login_system.py`

## Task 04 – Phishing Detection System
`phishing_detection_system.py`

Analyzes inputs (URLs/emails) for common phishing indicators.

## Tech Stack
- Python 3
- Standard library only (`hashlib`, `secrets`, `socket`, `urllib`, `re`, `time`)

## Author
Kushal M Gowda
