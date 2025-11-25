# nodehawk/cli/main.py
import argparse
import json
import os
from datetime import datetime
from typing import Dict, Any

from colorama import Fore, Style
from nodehawk.core.crawler import Crawler
from nodehawk.core.scanner import Scanner
from nodehawk.core.utils import format_url, RequestHandler
from nodehawk.core.vuln_checker import VulnerabilityChecker

def print_banner():
    """Prints the NodeHawk banner."""
    banner = fr"""{Fore.CYAN}
 _   _                       _   _            _    
| \ | | ___  _ __   ___   __| | | | __ _  ___| | __
|  \| |/ _ \| '_ \ / _ \ / _` | | |/ _` |/ __| |/ /
| |\  | (_) | | | | (_) | (_| | | | (_| | (__|   < 
|_| \_|\___/|_| |_|\___/ \__,_| |_|\__,_|\___|_|\_\ 
                                                  
      {Style.RESET_ALL}{Fore.YELLOW}A web reconnaissance and vulnerability scanner.{Style.RESET_ALL}
    """
    print(banner)

def run_scan(args: argparse.Namespace):
    """
    Orchestrates the scanning process based on command-line arguments.
    """
    target_url = format_url(args.url)
    print(f"[+] Starting scan for: {target_url}")

    # Initialize core components
    request_handler = RequestHandler()
    scanner = Scanner(target_url, request_handler)
    crawler = Crawler(target_url, request_handler)
    vuln_checker = VulnerabilityChecker(target_url, request_handler)

    # Master results dictionary
    results: Dict[str, Any] = {
        "scan_metadata": {
            "target_url": target_url,
            "scan_timestamp_utc": datetime.utcnow().isoformat(),
            "scan_options": vars(args)
        }
    }

    # --- Execute scans based on flags ---
    is_full_scan = args.full_scan

    if is_full_scan or args.headers:
        print("[*] Running Header Scan...")
        results["headers"] = scanner.scan_headers()

    if is_full_scan or args.ssl:
        print("[*] Running SSL Certificate Scan...")
        results["ssl_certificate"] = scanner.scan_ssl()

    if is_full_scan or args.crawl or args.deep:
        print("[*] Running Crawl and Sitemap Analysis...")
        results["crawl"] = crawler.run_crawl(deep=args.deep)

    if is_full_scan or args.vulns:
        print("[*] Running Vulnerability Checks...")
        results["vulnerabilities"] = vuln_checker.run_all_checks()

    # --- Output results ---
    print("\n[+] Scan Complete. Summary:")
    print_summary(results)

    if args.json_output:
        save_json_output(results, args.json_output)

def print_summary(results: Dict[str, Any]):
    """Prints a high-level summary of the scan results to the console."""
    if "headers" in results and results["headers"]:
        status = results["headers"].get('status_code', 'N/A')
        server = results["headers"].get('server_info', {}).get('server', 'N/A')
        print(f"  - HTTP Status: {status}, Server: {server}")

    if "ssl_certificate" in results and results["ssl_certificate"]:
        if "error" in results["ssl_certificate"]:
            print(f"  - SSL Status: {results['ssl_certificate']['error']}")
        else:
            expiry = results["ssl_certificate"].get('valid_until', 'N/A')
            expired = results["ssl_certificate"].get('has_expired', True)
            match = results["ssl_certificate"].get('domain_match', False)
            print(f"  - SSL Certificate: Expires on {expiry} (Expired: {expired}, Domain Match: {match})")

    if "crawl" in results and results["crawl"]:
        robots = results["crawl"].get("robots_txt", {})
        sitemap = results["crawl"].get("sitemap", {})
        print(f"  - Robots.txt: {'Found' if robots.get('exists') else 'Not Found'}, Sitemap URLs: {len(sitemap.get('urls', []))}")

    if "vulnerabilities" in results and results["vulnerabilities"]:
        headers = results["vulnerabilities"].get("security_headers", {})
        sqli = results["vulnerabilities"].get("sql_injection", {})
        xss = results["vulnerabilities"].get("cross_site_scripting", {})
        print(f"  - Security Headers: {len(headers.get('missing_headers', []))} missing")
        print(f"  - SQL Injection: Vulnerable - {sqli.get('vulnerable', False)}")
        print(f"  - Reflected XSS: Vulnerable - {xss.get('vulnerable', False)}")


def save_json_output(results: Dict[str, Any], path: str):
    """Saves the full results dictionary to a JSON file."""
    log_dir = os.path.join("output", "logs")
    
    try:
        # Ensure the output directory exists
        os.makedirs(log_dir, exist_ok=True)
        
        # Sanitize filename and join with the log directory
        filename = os.path.basename(path)
        if not filename.lower().endswith('.json'):
            filename += '.json'
            
        full_path = os.path.join(log_dir, filename)

        print(f"\n[+] Saving full report to: {full_path}")
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
            
    except (IOError, OSError) as e:
        print(f"\n[!] Error: Could not save JSON output to {path}. Reason: {e}")

def main():
    """
    Main entry point for the NodeHawk CLI.
    """
    print_banner()
    parser = argparse.ArgumentParser(
        description="NodeHawk: A web reconnaissance and vulnerability scanning tool.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Required Argument ---
    parser.add_argument(
        "--url",
        required=True,
        help="The target URL to scan (e.g., https://example.com)."
    )

    # --- Scan Type Flags ---
    scan_group = parser.add_argument_group('Scan Types')
    scan_group.add_argument(
        "--headers",
        action="store_true",
        help="Only show HTTP headers and server info."
    )
    scan_group.add_argument(
        "--vulns",
        action="store_true",
        help="Run all vulnerability checks (SQLi, XSS, Headers)."
    )
    scan_group.add_argument(
        "--crawl",
        action="store_true",
        help="Perform a basic crawl of the main page and parse robots.txt."
    )
    scan_group.add_argument(
        "--deep",
        action="store_true",
        help="Perform a multi-page crawl using sitemap if available."
    )
    scan_group.add_argument(
        "--ssl",
        action="store_true",
        help="Run SSL/TLS certificate inspection."
    )
    scan_group.add_argument(
        "--full-scan",
        action="store_true",
        help="Run all available scanning modules."
    )

    # --- Output Flags ---
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "--json-output",
        metavar="PATH",
        help="Save the full scan results as a JSON file in output/logs/."
    )

    args = parser.parse_args()

    # If no specific scan type is chosen, default to a basic set of scans
    is_any_scan_flag = any([args.headers, args.vulns, args.crawl, args.deep, args.ssl, args.full_scan])
    if not is_any_scan_flag:
        print("[!] No scan type specified. Running a default scan (headers, ssl, basic crawl).")
        args.headers = True
        args.ssl = True
        args.crawl = True

    run_scan(args)


if __name__ == "__main__":
    main()