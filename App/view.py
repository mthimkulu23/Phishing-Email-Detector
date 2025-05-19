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

def display_menu():
    print("\033[1;31m")  # Bright red color
    print(r"""
    ██████╗  ██╗  ██╗ ██╗ ███████╗ ██╗  ██████╗ ██╗  ██╗
    ██╔══██╗ ██║  ██║ ██║ ██╔════╝ ██║ ██╔════╝ ██║ ██╔╝
    ██████╔╝ ███████║ ██║ █████╗   ██║ ██║      █████╔╝ 
    ██╔═══╝  ██╔══██║ ██║ ██╔══╝   ██║ ██║      ██╔═██╗ 
    ██║      ██║  ██║ ██║ ██║      ██║ ╚██████╗ ██║  ██╗
    ╚═╝      ╚═╝  ╚═╝ ╚═╝ ╚═╝      ╚═╝  ╚═════╝ ╚═╝  ╚═╝
    """)
    print("\033[1;33m")  # Bright yellow for the title
    print("          P H I S H I N G   D E T E C T I O N   T O O L")
    print("\033[0m")  # Reset color
    print("\033[1;32mBuilt by Thabang Mthimkulu - Technical Cybersecurity\033[0m\n")
    
    print("\033[1;36m" + "="*60 + "\033[0m")  # Bright cyan separator
    print("\033[1;34mCHOOSE AN OPTION:\033[0m".center(60))
    print("\033[1;36m" + "="*60 + "\033[0m")
    print("\033[1m1. Analyze Email Content\033[0m")
    print("\033[1m2. Analyze a URL\033[0m")
    print("\033[1m3. Analyze Email from File\033[0m")
    print("\033[1m4. Exit\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

def main():
    while True:
        display_menu()
        choice = input("\nEnter your choice (1 - 4): ").strip()
        
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
            url = input("\nEnter the URL to check: ").strip()
            print("\n=== URL Analysis Report ===\n")
            results = analyze_url(url)
            if results['flags']:
                for flag in results['flags']:
                    print(f" - {flag}")
                print(f"\nScore: {results['score']}")
                print(f"Verdict: {results['verdict']}")
            else:
                print("\033[1;32mNo suspicious indicators found in the URL.\033[0m")
        
        elif choice == '3':
            filename = input("\nEnter file path: ").strip()
            try:
                with open(filename, 'r', encoding='utf-8') as f:  # Force UTF-8 encoding
                    email_content = f.read()
                report = run_analysis(email_content)
                print_report(report)
            except FileNotFoundError:
                print(f"\033[1;31mFile not found: {filename}\033[0m")
            except UnicodeDecodeError:
                try:
                    with open(filename, 'r', encoding='latin-1') as f:  # Fallback encoding
                        email_content = f.read()
                    report = run_analysis(email_content)
                    print_report(report)
                except Exception as e:
                    print(f"\033[1;31mError reading file: {e}\033[0m")
            except Exception as e:
                print(f"\033[1;31mError: {e}\033[0m")
        
        elif choice == '4':
            print("\nExiting... Goodbye!")
            sys.exit(0)
        
        else:
            print("\033[1;31mInvalid option. Please enter a number between 1 and 4.\033[0m")
        
        # Add a pause before showing menu again
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()