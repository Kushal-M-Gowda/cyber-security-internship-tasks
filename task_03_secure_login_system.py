"""
Task 03 - Secure Login System with Attack Prevention
IncodeVision Cyber Security Internship

Features:
- User registration
- Password hashing using PBKDF2-HMAC-SHA256
- Secure login verification
- Failed login attempt tracking
- Temporary account lockout
- Password strength validation
"""

import hashlib
import secrets
import re
import time


users = {}

MAX_ATTEMPTS = 3
LOCKOUT_TIME = 30


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000
    )


def password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        score += 1

    return score


def register():
    print("\n--- User Registration ---")

    username = input("Enter username: ").strip()

    if username in users:
        print("[ERROR] Username already exists.")
        return

    password = input("Enter password: ")
    score = password_strength(password)

    print(f"Password Strength Score: {score}/5")

    if score < 3:
        print("[ERROR] Password is too weak.")
        print("Use at least 8 characters.")
        print("Include uppercase and lowercase letters.")
        print("Include a number and special character.")
        return

    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)

    users[username] = {
        "salt": salt,
        "password_hash": password_hash,
        "failed_attempts": 0,
        "locked_until": 0
    }

    print("[SUCCESS] Registration completed.")


def login():
    print("\n--- Secure Login ---")

    username = input("Enter username: ").strip()
    password = input("Enter password: ")

    if username not in users:
        print("[ERROR] Invalid username or password.")
        return

    user = users[username]
    current_time = time.time()

    if current_time < user["locked_until"]:
        remaining = int(user["locked_until"] - current_time)
        print("[BLOCKED] Account temporarily locked.")
        print(f"Try again after {remaining} seconds.")
        return

    entered_hash = hash_password(password, user["salt"])

    if secrets.compare_digest(
        entered_hash,
        user["password_hash"]
    ):
        user["failed_attempts"] = 0
        print("\n[SUCCESS] Login successful!")
        print(f"Welcome, {username}.")

    else:
        user["failed_attempts"] += 1
        remaining_attempts = (
            MAX_ATTEMPTS - user["failed_attempts"]
        )

        print("\n[ERROR] Invalid username or password.")

        if user["failed_attempts"] >= MAX_ATTEMPTS:
            user["locked_until"] = time.time() + LOCKOUT_TIME
            user["failed_attempts"] = 0

            print("[SECURITY] Too many failed attempts.")
            print(f"Account locked for {LOCKOUT_TIME} seconds.")
        else:
            print(f"Attempts remaining: {remaining_attempts}")


def main():
    print("======================================")
    print("       SECURE LOGIN SYSTEM")
    print("======================================")

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Exiting Secure Login System...")
            break
        else:
            print("[ERROR] Invalid option.")


if __name__ == "__main__":
    main()
