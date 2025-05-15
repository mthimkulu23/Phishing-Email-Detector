import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    'verify', 'account', 'login', 'update', 'urgent', 'security',
    'alert', 'important', 'action required', 'suspended', 'bank',
    'paypal', 'irs', 'password', 'credentials', 'click here'
]

def analyze_headers(headers):
    suspicious_flags = []

    from_header = re.search(r'From:.*?<([^>]+)>', headers, re.IGNORECASE)
    reply_to_header = re.search(r'Reply-To:.*?<([^>]+)>', headers, re.IGNORECASE)

    if from_header:
        from_email = from_header.group(1)
        if '@' not in from_email:
            suspicious_flags.append(f"Invalid From address (missing '@'): {from_email}")
    else:
        suspicious_flags.append("No valid 'From' header found or wrong format.")

    if reply_to_header:
        reply_email = reply_to_header.group(1)
        if '@' not in reply_email:
            suspicious_flags.append(f"Invalid Reply-To address (missing '@'): {reply_email}")
    else:
        suspicious_flags.append("Missing 'Reply-To' header.")

    if from_header and reply_to_header:
        from_domain = from_email.split('@')[-1]
        reply_domain = reply_email.split('@')[-1]
        if from_domain.lower() != reply_domain.lower():
            suspicious_flags.append(f"Mismatched From/Reply-To domains: {from_domain} vs {reply_domain}")

    if 'X-Mailer' not in headers and 'X-Originating-IP' not in headers:
        suspicious_flags.append("Missing important headers (possible spoofing)")

    return suspicious_flags

def analyze_links(text):
    suspicious_links = []
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    trusted_domains = ['paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'github.com', 'chatgpt.com', 'shaper.co.za']
    phishing_domains = ['paypal-update', 'secure-paypal', 'login', 'account', 'verify']

    urls = url_pattern.findall(text)

    for url in urls:
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc.lower()

            if any(td in domain for td in phishing_domains):
                suspicious_links.append(f"Suspicious domain (untrusted): {url}")
                continue

            if any(domain.endswith(td) for td in trusted_domains):
                continue

            if parsed.scheme != 'https':
                suspicious_links.append(f"Insecure (non-HTTPS) URL: {url}")

            if ip_pattern.search(domain):
                suspicious_links.append(f"URL contains IP address: {url}")
                continue

            shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
            if any(s in domain for s in shorteners):
                suspicious_links.append(f"URL shortener detected: {url}")
                continue

            parts = domain.split('.')
            if len(parts) > 2 and parts[-2] not in ['com', 'net', 'org']:
                suspicious_links.append(f"Suspicious subdomain structure: {url}")

        except Exception as e:
            suspicious_links.append(f"Error parsing URL {url}: {e}")

    return suspicious_links

def analyze_content(text):
    suspicious_content = []
    text_lower = text.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            suspicious_content.append(f"Phishing keyword detected: {keyword}")

    return suspicious_content

def extract_headers(email_content):
    parts = email_content.splitlines()
    split_index = 0
    for i in range(len(parts)):
        if parts[i].strip() == "":
            split_index = i
            break
    headers = "\n".join(parts[:split_index])
    return headers
