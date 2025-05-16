import ipaddress
import tldextract
from urllib.parse import urlparse
from datetime import datetime
import whois
from .model import PhishingAnalyzer

analyzer = PhishingAnalyzer()

def run_analysis(email_content):
    return analyzer.analyze_email(email_content)

def analyze_url(url):
    flags = []
    score = 0
    
    # Add https:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        # List of trusted domains
        trusted_domains = {
            'paypal.com', 'google.com', 'amazon.com', 
            'microsoft.com', 'apple.com', 'linkedin.com',
            'netflix.com', 'facebook.com', 'twitter.com',
            'paypal.me', 'accounts.google.com'
        }
        
        # Check against trusted domains first
        if domain in trusted_domains:
            return {
                'flags': [],
                'score': 0,
                'verdict': "Legitimate domain (trusted)"
            }
        
        # Typosquatting detection for popular services
        popular_services = {
            'paypal': ['paypa1', 'paypai', 'paypai', 'paypaI'],
            'google': ['go0gle', 'g00gle', 'googel'],
            'amazon': ['amaz0n', 'amaz0n', 'amaz0n'],
            'microsoft': ['micros0ft', 'rnicrosoft'],
            'apple': ['appie', 'aple']
        }
        
        for service, typos in popular_services.items():
            if any(typo in domain for typo in typos):
                flags.append(f"Possible typosquatting: {url} (looks like {service})")
                score += 4
                break
        
        # Check for HTTPS
        if parsed.scheme != 'https':
            flags.append("URL uses HTTP instead of HTTPS (insecure)")
            score += 1
        
        # Check for IP address in URL
        netloc = parsed.netloc.split(':')[0]
        if any(char.isdigit() for char in netloc):
            try:
                ipaddress.ip_address(netloc)
                flags.append("URL uses IP address instead of domain")
                score += 3
            except:
                pass
        
        # Check for suspicious TLDs
        suspicious_tlds = {'.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'}
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            flags.append(f"Suspicious domain TLD: {domain}")
            score += 2
        
        # Check for subdomain tricks
        if extracted.subdomain and any(
            service in extracted.subdomain 
            for service in ['paypal', 'google', 'amazon', 'microsoft', 'apple']
        ):
            flags.append(f"Suspicious subdomain usage: {url}")
            score += 3
        
        # Check domain age (new domains are more suspicious)
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
        
    except Exception as e:
        flags.append(f"URL parsing error: {str(e)}")
        score += 1
    
    return {
        'flags': flags,
        'score': score,
        'verdict': analyzer.get_verdict(score)
    }