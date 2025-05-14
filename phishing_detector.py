#!/usr/bin/env python3
import re
import sys
from urllib.parse import urlparse

# Common phishing keywords
PHISHING_KEYWORDS = [
    'verify', 'account', 'login', 'update', 'urgent', 'security',
    'alert', 'important', 'action required', 'suspended', 'bank',
    'paypal', 'irs', 'password', 'credentials', 'click here'
]

def analyze_headers(headers):
    """Analyze email headers for suspicious patterns"""
    suspicious_flags = []

    from_header = re.search(r'From:.*?<([^>]+)>', headers, re.IGNORECASE)
    reply_to_header = re.search(r'Reply-To:.*?<([^>]+)>', headers, re.IGNORECASE)

    # Check if "From" header exists
    if from_header:
        from_email = from_header.group(1)
        if '@' not in from_email:
            suspicious_flags.append(f"Invalid From address (missing '@'): {from_email}")
    else:
        suspicious_flags.append("Missing 'From' header.")

    # Check if "Reply-To" header exists
    if reply_to_header:
        reply_email = reply_to_header.group(1)
        if '@' not in reply_email:
            suspicious_flags.append(f"Invalid Reply-To address (missing '@'): {reply_email}")
    else:
        suspicious_flags.append("Missing 'Reply-To' header.")

    # Compare domains
    if from_header and reply_to_header:
        from_domain = from_email.split('@')[-1]
        reply_domain = reply_email.split('@')[-1]
        if from_domain.lower() != reply_domain.lower():
            suspicious_flags.append(f"Mismatched From/Reply-To domains: {from_domain} vs {reply_domain}")

    # Check for spoofing
    if 'X-Mailer' not in headers and 'X-Originating-IP' not in headers:
        suspicious_flags.append("Missing important headers (possible spoofing)")

    return suspicious_flags

def analyze_links(text):
    """Analyze text or a single URL for suspicious links"""
    suspicious_links = []
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    # List of trusted domains (can add more or use a more sophisticated check)
    trusted_domains = ['paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'github.com']

    # List of common phishing words that can be in the domain
    phishing_domains = ['paypal-update', 'secure-paypal', 'login', 'account', 'verify']

    urls = url_pattern.findall(text)

    for url in urls:
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc.lower()

            # Check if the domain is suspicious (mimicking trusted domains)
            if any(td in domain for td in phishing_domains):
                suspicious_links.append(f"Suspicious domain (mimicking trusted domains): {url}")
                continue  # Skip further checks for these

            # Check if domain matches a trusted domain
            if any(domain.endswith(td) for td in trusted_domains):
                continue  # skip further analysis for trusted domains

            # Flag non-HTTPS URLs
            if parsed.scheme != 'https':
                suspicious_links.append(f"Insecure (non-HTTPS) URL: {url}")

            # Flag IP address usage
            if ip_pattern.search(domain):
                suspicious_links.append(f"URL contains IP address: {url}")
                continue

            # Check for URL shorteners
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
            if any(s in domain for s in shorteners):
                suspicious_links.append(f"URL shortener detected: {url}")
                continue

            # Check for suspicious subdomain structure
            parts = domain.split('.')
            if len(parts) > 2 and parts[-2] not in ['com', 'net', 'org']:
                suspicious_links.append(f"Suspicious subdomain structure: {url}")

        except Exception as e:
            suspicious_links.append(f"Error parsing URL {url}: {e}")

    return suspicious_links

def analyze_content(text):
    """Analyze email content for phishing keywords"""
    suspicious_content = []
    text_lower = text.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            suspicious_content.append(f"Phishing keyword detected: {keyword}")

    return suspicious_content

def main():
    print("=== Phishing Detection Tool ===")
    print("Choose an option:")
    print("1. Analyze Email Content")
    print("2. Analyze a URL")

    choice = input("Enter 1 or 2: ").strip()

    if choice == '1':
        print("\nPaste the full email content below. Press Enter twice to finish:")
        lines = []
        while True:
            try:
                line = input()
                if line == '':
                    break
                lines.append(line)
            except KeyboardInterrupt:
                print("\nInput interrupted.")
                return

        email_content = '\n'.join(lines)

        print("\n=== Phishing Email Analysis Report ===\n")

        # Try to split headers and body using double newline
        headers = ''
        headers_end = email_content.find('\n\n')
        if headers_end != -1:
            headers = email_content[:headers_end]
        else:
            headers = email_content

        header_flags = analyze_headers(headers)
        if header_flags:
            print("Suspicious Headers Detected:")
            for flag in header_flags:
                print(f" - {flag}")
        else:
            print("No suspicious headers detected.")

        link_flags = analyze_links(email_content)
        if link_flags:
            print("\nSuspicious Links Detected:")
            for flag in link_flags:
                print(f" - {flag}")
        else:
            print("\nNo suspicious links detected.")

        content_flags = analyze_content(email_content)
        if content_flags:
            print("\nSuspicious Content Detected:")
            for flag in content_flags:
                print(f" - {flag}")
        else:
            print("\nNo suspicious content detected.")

    elif choice == '2':
        url = input("Enter the URL to check: ").strip()
        print("\n=== URL Analysis Report ===\n")
        results = analyze_links(url)
        if results:
            for flag in results:
                print(f" - {flag}")
        else:
            print("No suspicious indicators found in the URL.")

    else:
        print("Invalid option. Please enter 1 or 2.")

    print("\n=== Analysis Complete ===")

if __name__ == "__main__":
    main()
