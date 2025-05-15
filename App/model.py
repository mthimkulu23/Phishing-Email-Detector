import re
from urllib.parse import urlparse

# Extract headers using simple split
def extract_headers(email_content):
    header_part = email_content.split('\n\n')[0]
    headers = {}
    for line in header_part.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers

def analyze_headers(headers):
    flags = []
    if 'Received' not in headers:
        flags.append("Missing 'Received' header – may hide original sender.")
    if 'From' in headers and 'Reply-To' in headers and headers['From'] != headers['Reply-To']:
        flags.append("'From' and 'Reply-To' mismatch.")
    if 'Return-Path' in headers and headers['Return-Path'] != headers.get('From', ''):
        flags.append("'Return-Path' differs from 'From' header.")
    return flags

def analyze_links(content):
    flags = []
    urls = re.findall(r'(https?://[^\s]+)', content)
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc and 'secure' not in parsed.netloc.lower():
            flags.append(f"Suspicious link: {url}")
        if parsed.netloc.endswith('.ru') or parsed.netloc.endswith('.cn'):
            flags.append(f"Link points to foreign domain: {url}")
    return flags

def analyze_content(content):
    flags = []
    content_lower = content.lower()
    phishing_keywords = [
        "verify your account", "update your information", "suspended account",
        "click here to login", "password expires", "urgent action required",
        "you've won", "reset your password", "confirm your identity"
    ]
    for keyword in phishing_keywords:
        if keyword in content_lower:
            flags.append(f"Keyword detected: '{keyword}'")

    if re.search(r'\d{4} \d{4} \d{4} \d{4}', content):  # credit card pattern
        flags.append("Possible credit card number found.")

    if re.search(r'(?i)ssn[:\s]*\d{3}-\d{2}-\d{4}', content):
        flags.append("Possible SSN found.")

    return flags
