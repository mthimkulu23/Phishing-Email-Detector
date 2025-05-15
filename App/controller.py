from .model import PhishingAnalyzer

analyzer = PhishingAnalyzer()

def run_analysis(email_content):
    return analyzer.analyze_email(email_content)

def analyze_url(url):
    return analyzer.analyze_links(url)