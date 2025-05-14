# 🛡️ Phishing Detection Tool
This Python-based tool helps identify potential phishing attempts by analyzing email headers, email content, and URLs. It detects common phishing indicators like suspicious keywords, malicious domains, insecure URLs, and spoofed email headers.

# 🔍 Features

Email Content Analysis
Scans the body of emails for phishing keywords and suspicious content.

URL Analysis
Checks URLs for:

Insecure protocols (non-HTTPS)

Use of IP addresses

URL shorteners

Phishing domain patterns

Email Header Analysis
Examines "From" and "Reply-To" headers for signs of spoofing and domain mismatches.

# 🧰 Requirements

Python 3.x

No external libraries required. The following standard Python modules are used:

re

sys

urllib.parse

# ⚙️ Installation

git clone https://github.com/mthimkulu23/Phishing-Email-Detector.git

Navigate to the project directory

cd Phishing-Email-Detector

# ▶️ Usage
Run the tool:
python phishing_detector.py
Choose option 1 to analyze email content.

Paste the full email content (including headers). Press Enter twice to submit.

View the analysis report for suspicious content, links, and headers.

