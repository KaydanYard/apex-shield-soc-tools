# log_analyzer.py
# Apex Shield SOC Tools -- Log Analysis Utility
# Module 7 Project
# Reads an authentication log file, identifies failed login attempts,
# and generates a formatted analysis report.
#
# Usage:
#   python3 log_analyzer.py                          # sample_auth.log -> analysis_report.txt
#   python3 log_analyzer.py /var/log/auth.log        # analyze a different log
#   python3 log_analyzer.py auth.log -o report.txt   # choose the report name
#   python3 log_analyzer.py auth.log -v              # verbose: print every failed login
import argparse                     # argparse -- for command-line options
import os                           # os -- for file checks and script-relative paths
import re                           # Regular expressions -- for IP address extraction
import sys                          # sys -- for exiting with an error code
from datetime import datetime       # datetime -- for timestamping the report
from collections import Counter     # Counter -- for counting IP occurrences

# Folder this script lives in, so the defaults work from any working directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.join(SCRIPT_DIR, "sample_auth.log")
DEFAULT_REPORT = os.path.join(SCRIPT_DIR, "analysis_report.txt")


def parse_args():
    """
    Define and read the command-line options.

    Returns:
        argparse.Namespace: log_file, output, and verbose attributes
    """
    parser = argparse.ArgumentParser(
        description="Apex Shield SOC -- analyze an auth log for failed logins."
    )
    # nargs="?" makes the positional argument optional, falling back to the default
    parser.add_argument(
        "log_file",
        nargs="?",
        default=DEFAULT_LOG,
        help="path to the authentication log (default: sample_auth.log next to this script)",
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_REPORT,
        help="path for the report file (default: analysis_report.txt next to this script)",
    )
    # store_true: False unless -v is typed
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print every failed login line to the terminal",
    )
    return parser.parse_args()


def find_failed_logins(lines):
    """
    Filter a list of log lines to return only failed login attempts.

    Checks for two patterns:
    - Lines containing "Failed" (SSH failed password attempts)
    - Lines containing "authentication failure" (sudo/PAM failures)

    Parameters:
        lines (list): All log lines to search through

    Returns:
        list: Only the lines that represent failed logins
    """
    failed = []
    for line in lines:
        if "Failed" in line or "authentication failure" in line.lower():
            failed.append(line)
    return failed


def extract_ip_addresses(lines):
    """
    Extract all IP addresses from a list of log lines.

    Uses a regular expression to match IPv4 addresses in the format
    X.X.X.X where each X is 1-3 digits.

    Parameters:
        lines (list): Log lines to search for IP addresses

    Returns:
        list: All IP addresses found (may contain duplicates)
    """
    # This pattern matches IPv4 addresses: four groups of 1-3 digits
    # separated by dots, surrounded by word boundaries
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    all_ips = []
    for line in lines:
        # Returns a list of all matches in the line
        matches = ip_pattern.findall(line)

        # extend adds each item, not the list as one item
        all_ips.extend(matches)

    return all_ips


def print_failed_logins(failed_logins):
    """
    Verbose mode: print every failed login line, numbered.

    Parameters:
        failed_logins (list): All failed login log lines
    """
    print("\n[*] Verbose: all failed login attempts")
    width = len(str(len(failed_logins)))   # pad numbers so the lines align
    for number, entry in enumerate(failed_logins, start=1):
        print(f"    {number:>{width}}. {entry}")


def generate_report(failed_logins, ip_counts, log_file, output_file):
    """
    Write a formatted analysis report to a text file.

    Parameters:
        failed_logins (list): All failed login log lines
        ip_counts (Counter): IP addresses and their failure counts
        log_file (str): Path of the analyzed log (shown in the header)
        output_file (str): Path where the report should be saved

    Returns:
        None (creates the report file as a side effect)
    """
    # Get current timestamp for the report header
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w", encoding="utf-8") as f:
        # Report header
        f.write("=" * 55 + "\n")
        f.write("  APEX SHIELD SOC -- FAILED LOGIN ANALYSIS REPORT\n")
        f.write("=" * 55 + "\n")
        f.write(f"  Generated: {timestamp}\n")
        f.write(f"  Log File:  {os.path.basename(log_file)}\n")
        f.write("=" * 55 + "\n\n")

        # Summary section
        f.write(f"SUMMARY\n")
        f.write("-" * 30 + "\n")
        f.write(f"Total failed login attempts: {len(failed_logins)}\n")
        f.write(f"Unique source IPs: {len(ip_counts)}\n\n")

        # Top IPs section
        f.write("TOP SOURCE IP ADDRESSES\n")
        f.write("-" * 30 + "\n")
        for ip, count in ip_counts.most_common():
            # Flag IPs with 3 or more attempts
            flag = "  <-- INVESTIGATE" if count >= 3 else ""
            f.write(f"  {ip:<20} {count:>3} attempts{flag}\n")

        # Full failed login log
        f.write("\n\nFULL FAILED LOGIN LOG\n")
        f.write("-" * 30 + "\n")
        for entry in failed_logins:
            f.write(f"  {entry}\n")

    print(f"[+] Report written to: {output_file}")


def validate_log_file(filepath):
    """
    Confirm the log file exists, is a regular file, and is readable.
    Prints a clear error to stderr and exits with status 1 if any check fails.

    Parameters:
        filepath (str): the path the user supplied
    """
    if not os.path.exists(filepath):
        print(f"[!] ERROR: Log file not found: {filepath}", file=sys.stderr)
        print(f"[!] Checked: {os.path.abspath(filepath)}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(filepath):
        print(f"[!] ERROR: Not a file (is it a folder?): {filepath}", file=sys.stderr)
        sys.exit(1)
    if not os.access(filepath, os.R_OK):
        print(f"[!] ERROR: Permission denied reading: {filepath}", file=sys.stderr)
        sys.exit(1)


def read_log_file(filepath):
    """
    Read a log file and return all non-empty lines, stripped of whitespace.
    Call validate_log_file() first.

    Parameters:
        filepath (str): the path to the log file

    Returns:
        list: A list of non-empty strings, one per line
    """
    lines = []
    # errors="replace" keeps one bad byte from crashing the analysis
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            clean = line.strip()
            if clean:
                lines.append(clean)
    return lines


def main():
    """
    Main execution function.
    Orchestrates the log analysis workflow.
    """
    # Configuration -- comes from the command line (see parse_args)
    args = parse_args()
    log_file = args.log_file
    output_file = args.output

    print("\n" + "=" * 55)
    print("  APEX SHIELD -- LOG ANALYZER")
    print("=" * 55)

    # Step 1: Check the log file, then load it
    validate_log_file(log_file)             # exits with a clear error if missing
    print(f"\n[*] Reading log file: {log_file}")
    lines = read_log_file(log_file)

    if not lines:
        print("[!] Log file is empty. Nothing to analyze.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Loaded {len(lines)} log entries.")

    # Step 2: Find failed logins
    print("\n[*] Scanning for failed login attempts...")
    failed = find_failed_logins(lines)
    print(f"[+] Found {len(failed)} failed login attempts.")

    # Optional: verbose listing of every failure
    if args.verbose:
        print_failed_logins(failed)

    # Step 3: Extract IP addresses
    print("\n[*] Extracting source IP addresses...")
    ips = extract_ip_addresses(failed)
    ip_counts = Counter(ips)
    print(f"[+] Found {len(ip_counts)} unique source IP addresses.")

    # Step 4: Show summary to terminal
    print("\n[*] Top source IPs:")
    for ip, count in ip_counts.most_common(5):
        flag = "  <-- INVESTIGATE" if count >= 3 else ""
        print(f"    {ip:<20} {count:>3} failures{flag}")

    # Step 5: Generate the report
    print(f"\n[*] Writing report to: {output_file}")
    try:
        generate_report(failed, ip_counts, log_file, output_file)
    except OSError as e:
        print(f"[!] ERROR: Could not write report: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n[+] Analysis complete.")
    print("=" * 55 + "\n")


# This block runs main() when the script is executed directly
# It does NOT run when this file is imported as a module
if __name__ == "__main__":
    main()
