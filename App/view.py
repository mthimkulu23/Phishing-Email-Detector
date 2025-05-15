import sys
from . import controller

def print_report(report):
    print("\n=== Phishing Email Analysis Report ===\n")

    if report['headers']:
        print("Suspicious Headers Detected:")
        for flag in report['headers']:
            print(f" - {flag}")
    else:
        print("No suspicious headers detected.")

    if report['links']:
        print("\nSuspicious Links Detected:")
        for flag in report['links']:
            print(f" - {flag}")
    else:
        print("\nNo suspicious links detected.")

    if report['content']:
        print("\nSuspicious Content Detected:")
        for flag in report['content']:
            print(f" - {flag}")
    else:
        print("\nNo suspicious content detected.")

    print("\n=== Analysis Complete ===")

def main():
    print("\033[1;31m")
    print("██████╗ ██╗  ██╗██╗███████╗██╗ ██████╗██╗  ██╗")
    print("██╔══██╗██║  ██║██║██╔════╝██║██╔════╝██║ ██╔╝")
    print("██████╔╝███████║██║█████╗  ██║██║     █████╔╝ ")
    print("██╔═══╝ ██╔══██║██║██╔══╝  ██║██║     ██╔═██╗ ")
    print("██║     ██║  ██║██║██║     ██║╚██████╗██║  ██╗")
    print("╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝")
    print("             PHISHING DETECTION TOOL")
    print("\033[0m")
    print("Built by Thabang Mthimkulu - Technical Cybersecurity\n")

    print("Choose an option:")
    print("1. Analyze Email Content")
    print("2. Analyze a URL")
    print("3. Exit")
    print("4. Analyze Email from File")

    choice = input("Enter 1, 2, 3 or 4: ").strip()

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
        report = controller.run_analysis(email_content)
        print_report(report)

    elif choice == '2':
        url = input("Enter the URL to check: ").strip()
        print("\n=== URL Analysis Report ===\n")
        results = controller.run_analysis(url)['links']
        if results:
            for flag in results:
                print(f" - {flag}")
        else:
            print("No suspicious indicators found in the URL.")

    elif choice == '3':
        print("Exiting... Goodbye!")
        sys.exit(0)

    elif choice == '4':
        filename = input("Enter file path: ").strip()
        try:
            with open(filename, 'r') as f:
                email_content = f.read()
            report = controller.run_analysis(email_content)
            print_report(report)
        except FileNotFoundError:
            print(f"File not found: {filename}")
        except Exception as e:
            print(f"Error reading file: {e}")

    else:
        print("Invalid option. Please enter 1, 2, 3 or 4.")

if __name__ == "__main__":
    main()
