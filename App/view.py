import sys
from .controller import run_analysis, analyze_url

def print_report(report):
    print("\n=== Phishing Email Analysis Report ===\n")
    
    # Print header analysis
    if report['headers']:
        print("\033[1;31mSuspicious Headers Detected:\033[0m")
        for flag in report['headers']:
            print(f" - {flag}")
    else:
        print("\033[1;32mNo suspicious headers detected.\033[0m")
    
    # Print link analysis
    if report['links']:
        print("\n\033[1;31mSuspicious Links Detected:\033[0m")
        for flag in report['links']:
            print(f" - {flag}")
    else:
        print("\n\033[1;32mNo suspicious links detected.\033[0m")
    
    # Print content analysis
    if report['content']:
        print("\n\033[1;31mSuspicious Content Detected:\033[0m")
        for flag in report['content']:
            print(f" - {flag}")
    else:
        print("\n\033[1;32mNo suspicious content detected.\033[0m")
    
    # Print overall verdict
    print(f"\n\033[1;36mOverall Score: {report['score']}\033[0m")
    print(f"\033[1;35mVerdict: {report['verdict']}\033[0m")
    print("\n=== Analysis Complete ===")

def main():
    # ASCII art and menu remains the same
    # ...
    
    if choice == '1':
        print("\nPaste the full email content below. Press Enter twice to finish:")
        lines = []
        while True:
            try:
                line = input()
                if line == '':
                    if len(lines) >= 1 and lines[-1] == '':
                        break
                lines.append(line)
            except KeyboardInterrupt:
                print("\nInput interrupted.")
                return
        email_content = '\n'.join(lines)
        report = run_analysis(email_content)
        print_report(report)
    
    elif choice == '2':
        url = input("Enter the URL to check: ").strip()
        print("\n=== URL Analysis Report ===\n")
        results = analyze_url(url)
        if results['flags']:
            for flag in results['flags']:
                print(f" - {flag}")
            print(f"\nScore: {results['score']}")
            print(f"Verdict: {results['verdict']}")
        else:
            print("\033[1;32mNo suspicious indicators found in the URL.\033[0m")
    
    # Rest of the menu handling remains the same
    # ...