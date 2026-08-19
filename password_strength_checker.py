"""
Task 02 - Password Strength Checker
IncodeVision Cyber Security Internship

Checks a password for length, uppercase/lowercase letters,
numbers, and special characters, then classifies it as
Weak, Medium, or Strong and gives improvement suggestions.
"""

import re


def check_password_strength(password: str) -> dict:
    checks = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password)),
    }

    score = sum(checks.values())

    if score <= 2:
        strength = "Weak"
    elif score in (3, 4):
        strength = "Medium"
    else:
        strength = "Strong"

    suggestions = []
    if not checks["length"]:
        suggestions.append("Use at least 8 characters.")
    if not checks["uppercase"]:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not checks["lowercase"]:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not checks["digit"]:
        suggestions.append("Add at least one number (0-9).")
    if not checks["special"]:
        suggestions.append("Add at least one special character (!@#$%^&* etc.).")

    return {
        "password": password,
        "score": f"{score}/5",
        "strength": strength,
        "checks": checks,
        "suggestions": suggestions or ["Great job! Your password is strong."],
    }


def print_report(result: dict) -> None:
    print("\n--- Password Strength Report ---")
    print(f"Password entered : {'*' * len(result['password'])}")
    print(f"Score            : {result['score']}")
    print(f"Strength         : {result['strength']}")
    print("\nChecks:")
    for key, passed in result["checks"].items():
        status = "PASS" if passed else "FAIL"
        print(f"  {key.capitalize():<10}: {status}")
    print("\nSuggestions:")
    for tip in result["suggestions"]:
        print(f"  - {tip}")
    print("---------------------------------\n")


if __name__ == "__main__":
    print("=== Password Strength Checker ===")
    while True:
        pwd = input("Enter a password to check (or 'q' to quit): ")
        if pwd.lower() == "q":
            break
        report = check_password_strength(pwd)
        print_report(report)
