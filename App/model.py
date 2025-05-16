import re
from urllib.parse import urlparse
import tldextract
import ipaddress
import hashlib
import requests
from datetime import datetime
import whois
from bs4 import BeautifulSoup

class PhishingAnalyzer:
    def __init__(self):
        # Initialize with more comprehensive patterns and databases
        self.phishing_keywords = self._load_keywords()
        self.known_phishing_domains = set()
        self.suspicious_tlds = {'.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq'}
        self.load_known_phishing_domains()
        
    def _load_keywords(self):
        # More comprehensive keyword list
        return [
            "verify your account", "update your information", "suspended account",
            "click here to login", "password expires", "urgent action required",
            "you've won", "reset your password", "confirm your identity",
            "account verification", "security alert", "immediate action required",
            "unauthorized login attempt", "limited time offer", "account suspension",
            "verify your identity", "billing problem", "payment failed",
            "invoice attached", "urgent payment required", "action required: your account",
            "account locked", "unusual login activity", "important security notice"
        ]
    
    def load_known_phishing_domains(self):
        # Could load from external source or API
        try:
            response = requests.get("https://openphish.com/feed.txt")
            if response.status_code == 200:
                self.known_phishing_domains.update(response.text.splitlines())
        except:
            pass
    
    def extract_headers(self, email_content):
        header_part = email_content.split('\n\n')[0]
        headers = {}
        for line in header_part.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    
    def analyze_headers(self, headers):
        flags = []
        score = 0
        
        # SPF, DKIM, DMARC checks
        if 'received-spf' not in headers:
            flags.append("Missing SPF record - possible spoofing")
            score += 1
        if 'authentication-results' not in headers:
            flags.append("Missing authentication results header")
            score += 1
        elif 'dkim=pass' not in headers['authentication-results'].lower():
            flags.append("DKIM verification failed")
            score += 2
        elif 'dmarc=pass' not in headers['authentication-results'].lower():
            flags.append("DMARC verification failed")
            score += 2
            
        # Header inconsistencies
        if 'from' in headers and 'reply-to' in headers and headers['from'].lower() != headers['reply-to'].lower():
            flags.append("'From' and 'Reply-To' mismatch")
            score += 2
            
        if 'return-path' in headers and 'from' in headers and headers['return-path'].lower() != headers['from'].lower():
            flags.append("'Return-Path' differs from 'From' header")
            score += 1
            
        # Check for suspicious sender domains
        if 'from' in headers:
            from_header = headers['from']
            domain = self.extract_domain(from_header)
            if domain and self.is_suspicious_domain(domain):
                flags.append(f"Suspicious sender domain: {domain}")
                score += 3
                
        return {'flags': flags, 'score': score}
    
    def extract_domain(self, email_or_url):
        # Extract domain from email address or URL
        if '@' in email_or_url:
            return email_or_url.split('@')[-1].lower()
        try:
            extracted = tldextract.extract(email_or_url)
            return f"{extracted.domain}.{extracted.suffix}".lower()
        except:
            return None
    
    def is_suspicious_domain(self, domain):
        # Check against known phishing domains and suspicious TLDs
        if domain in self.known_phishing_domains:
            return True
            
        extracted = tldextract.extract(domain)
        tld = f".{extracted.suffix}".lower()
        return tld in self.suspicious_tlds
    
    def analyze_links(self, content):
        flags = []
        score = 0
        urls = re.findall(r'(https?://[^\s]+)', content)
        
        for url in urls:
            parsed = urlparse(url)
            domain = self.extract_domain(url)
            
            # Check if URL is in known phishing database
            if domain in self.known_phishing_domains:
                flags.append(f"Known phishing domain: {url}")
                score += 5
                continue
                
            # Check for IP address in URL
            if any(char.isdigit() for char in parsed.netloc.split('.')[0]):
                try:
                    ipaddress.ip_address(parsed.netloc.split(':')[0])
                    flags.append(f"URL uses IP address instead of domain: {url}")
                    score += 3
                except:
                    pass
                    
            # Check for URL shortening services
            if any(service in parsed.netloc for service in ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'buff.ly','cutt.ly','adf.ly', 'bc.vc', 'clk.sh', 'shorturl.at', 'rb.gy', 'rb.gy', 'bit.do', 'clicky.me', 'discord-gift.com', 'steamcommumity.com', 'paypai.com', 'netflix-gift.com', 'microsoft-verify.com', 'amazon-offers.com', 'appleid-verify.com', 'bankofamerica-secure.com', 'dropbox-hr.com', 'whatsapp-chat.com','verify-account']):
                flags.append(f"URL uses shortening service: {url}")
                score += 2
                
            # Check for @ in URL (possible credential phishing)
            if '@' in url:
                flags.append(f"URL contains @ symbol (possible credential phishing): {url}")
                score += 3
                
            # Check for non-standard ports
            if ':' in parsed.netloc and not parsed.netloc.endswith((':80', ':443')):
                flags.append(f"URL uses non-standard port: {url}")
                score += 1
                
            # Check for suspicious TLDs
            if domain and self.is_suspicious_domain(domain):
                flags.append(f"Link points to suspicious domain: {url}")
                score += 2
                
            # Check for HTTPS
            if not parsed.scheme.startswith('https'):
                flags.append(f"Insecure HTTP link (not HTTPS): {url}")
                score += 1
                
            # Check for domain age (requires WHOIS lookup)
            try:
                domain_info = whois.whois(domain)
                if hasattr(domain_info, 'creation_date'):
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    if (datetime.now() - creation_date).days < 30:
                        flags.append(f"Newly registered domain (<30 days): {domain}")
                        score += 2
            except:
                pass
                
        return {'flags': flags, 'score': score}
    
    def analyze_content(self, content):
        flags = []
        score = 0
        content_lower = content.lower()
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                flags.append(f"Phishing keyword detected: '{keyword}'")
                score += 1
                
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediate', 'required', 'now', 'hurry', 'limited time']
        if any(word in content_lower for word in urgency_words):
            flags.append("Content creates sense of urgency")
            score += 1
            
        # Check for personal information requests
        personal_info = ['ssn', 'social security', 'credit card', 'password', 'account number']
        if any(info in content_lower for info in personal_info):
            flags.append("Content requests personal information")
            score += 2
            
        # Check for suspicious patterns
        if re.search(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', content):  # credit card
            flags.append("Possible credit card number found")
            score += 3
            
        if re.search(r'(?i)(ssn|social security number)[:\s-]*\d{3}[\s-]?\d{2}[\s-]?\d{4}', content):
            flags.append("Possible SSN found")
            score += 3
            
        # Check for HTML content
        if '<html' in content_lower or '<body' in content_lower:
            soup = BeautifulSoup(content, 'html.parser')
            # Check for hidden text
            hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x.lower())
            if hidden_elements:
                flags.append("Hidden text detected in HTML content")
                score += 2
                
            # Check for form elements
            if soup.find('form'):
                flags.append("HTML form detected - possible credential harvesting")
                score += 3
                
        return {'flags': flags, 'score': score}
    
    def analyze_email(self, email_content):
        headers = self.extract_headers(email_content)
        header_analysis = self.analyze_headers(headers)
        link_analysis = self.analyze_links(email_content)
        content_analysis = self.analyze_content(email_content)
        
        total_score = header_analysis['score'] + link_analysis['score'] + content_analysis['score']
        
        return {
            'headers': header_analysis['flags'],
            'links': link_analysis['flags'],
            'content': content_analysis['flags'],
            'score': total_score,
            'verdict': self.get_verdict(total_score)
        }
    
    def get_verdict(self, score):
        if score >= 10:
            return "HIGH confidence of phishing"
        elif score >= 5:
            return "MODERATE confidence of phishing"
        elif score >= 3:
            return "LOW confidence of phishing"
        else:
            return "Likely legitimate"