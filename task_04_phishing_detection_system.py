"""
Task 04 - Phishing Detection System (URL & Email Analysis)
IncodeVision Cyber Security Internship

Analyzes a URL or a block of email text for common phishing
indicators (suspicious keywords, fake/lookalike domains,
unusual URL patterns) and classifies it as Safe or Suspicious.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent action required", "suspended",
    "click here", "confirm your identity", "update your payment",
    "login immediately", "limited time", "winner", "free gift",
    "password expired", "unusual activity", "security alert",
]

TRUSTED_LOOKALIKE_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "netflix",
    "bankofamerica", "facebook", "instagram",
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd"]


def analyze_url(url: str) -> dict:
    findings = []
    score = 0

    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower()

    if not url.startswith("https://"):
        findings.append("URL does not use HTTPS.")
        score += 1

    if any(short in domain for short in SHORTENER_DOMAINS):
        findings.append("URL uses a link-shortening service (hides real destination).")
        score += 2

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        findings.append("Domain is a raw IP address, not a normal domain name.")
        score += 2

    if domain.count("-") >= 2:
        findings.append("Domain contains multiple hyphens (common in fake domains).")
        score += 1

    if len(domain) > 30:
        findings.append("Domain name is unusually long.")
        score += 1

    for brand in TRUSTED_LOOKALIKE_BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            findings.append(f"Domain mimics '{brand}' but is not the official domain.")
            score += 3

    if re.search(r"@", url):
        findings.append("URL contains '@', which can be used to hide the real destination.")
        score += 2

    return {"target": url, "score": score, "findings": findings}


def analyze_email_text(text: str) -> dict:
    findings = []
    score = 0
    lower_text = text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_text:
            findings.append(f"Contains suspicious phrase: '{keyword}'")
            score += 2

    urls_in_text = re.findall(r"(https?://\S+|www\.\S+)", text)
    for u in urls_in_text:
        url_result = analyze_url(u)
        score += url_result["score"]
        findings.extend(url_result["findings"])

    if re.search(r"[A-Z]{5,}", text):
        findings.append("Contains excessive capital letters (common urgency tactic).")
        score += 1

    return {"target": text, "score": score, "findings": findings}


def classify(score: int) -> str:
    return "Suspicious (likely phishing)" if score >= 3 else "Safe (low risk)"


def print_report(result: dict) -> None:
    print("\n--- Phishing Detection Report ---")
    print(f"Risk score : {result['score']}")
    print(f"Verdict    : {classify(result['score'])}")
    if result["findings"]:
        print("Indicators found:")
        for f in result["findings"]:
            print(f"  - {f}")
    else:
        print("No suspicious indicators found.")
    print("----------------------------------\n")


if __name__ == "__main__":
    print("=== Phishing Detection System ===")
    print("1. Analyze a URL")
    print("2. Analyze email text")
    while True:
        choice = input("\nChoose an option (1/2, or 'q' to quit): ").strip()
        if choice.lower() == "q":
            break
        elif choice == "1":
            url = input("Enter the URL: ")
            print_report(analyze_url(url))
        elif choice == "2":
            print("Paste the email text (end with an empty line):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            print_report(analyze_email_text("\n".join(lines)))
        else:
            print("Invalid choice.")
