# Phishing Detection Tool

This tool helps identify potential phishing attempts by analyzing email headers, email content, and URLs. It checks for common phishing indicators like suspicious keywords, malicious domains, insecure URLs, and spoofed email headers. It can be used to assess whether an email or URL might be part of a phishing attempt.

# Features
Email Content Analysis: Checks for phishing keywords and suspicious content in email body text.

URL Analysis: Verifies if a URL is potentially suspicious, checking for insecure protocols (non-HTTPS), IP addresses, URL shorteners, and phishing domain patterns.

Email Header Analysis: Identifies possible spoofing by analyzing "From" and "Reply-To" headers and comparing domain names.

# Requirements
To run this tool, you need to have the following installed:

Python 3.x

re module (comes by default with Python)

sys module (comes by default with Python)

urllib.parse module (comes by default with Python)

Installation
Clone this repository:

bash
Copy
Edit
git clone https://github.com/mthimkulu23/Phishing-Email-Detector.git
Navigate to the project directory:

bash
Copy
Edit
cd phishing-detection-tool
This tool requires no external libraries, as it uses only Python's built-in modules.

Usage
Option 1: Analyze Email Content
Run the tool:

bash
Copy
Edit
python phishing_detection_tool.py
Choose 1 to analyze email content.

Paste the full email content into the terminal (headers and body). Press Enter twice when you're done.

The tool will analyze the content for phishing keywords, suspicious links, and email header anomalies.

Option 2: Analyze a URL
Run the tool:

bash
Copy
Edit
python phishing_detection_tool.py
Choose 2 to analyze a URL.

Enter the URL you want to check.

The tool will analyze the URL for phishing indicators, such as suspicious domains, insecure protocols, and other red flags.

Example Output
When analyzing an email, the output may look like this:

yaml
Copy
Edit
=== Phishing Email Analysis Report ===

Suspicious Headers Detected:
 - Invalid From address (missing '@'): example@domain
 - Mismatched From/Reply-To domains: domain.com vs suspicious.com

Suspicious Links Detected:
 - Insecure (non-HTTPS) URL: http://example.com/phishing-link
 - Suspicious domain (mimicking trusted domains): http://secure-paypal-update.com

Suspicious Content Detected:
 - Phishing keyword detected: account
 - Phishing keyword detected: urgent
For URL analysis, the output might look like:

pgsql
Copy
Edit
=== URL Analysis Report ===

Suspicious domain (mimicking trusted domains): http://secure-paypal-update.com
Insecure (non-HTTPS) URL: http://example.com/phishing-link
Contributing
Contributions are welcome! If you have suggestions or improvements, please fork the repository and submit a pull request.

