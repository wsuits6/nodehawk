# nodehawk/cli/main.py
import argparse
import json
import os
from datetime import datetime
from typing import Dict, Any

from colorama import Fore, Style, init
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
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting scan for: {Fore.YELLOW}{target_url}{Style.RESET_ALL}")

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
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running Header Scan...")
        results["headers"] = scanner.scan_headers()

    if is_full_scan or args.ssl:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running SSL Certificate Scan...")
        results["ssl_certificate"] = scanner.scan_ssl()

    if is_full_scan or args.crawl or args.deep:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running Crawl and Sitemap Analysis...")
        results["crawl"] = crawler.run_crawl(deep=args.deep)

    if is_full_scan or args.vulns:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running Vulnerability Checks...")
        results["vulnerabilities"] = vuln_checker.run_all_checks()

    # --- Output results ---
    print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Scan Complete. Summary:")
    print_summary(results)

    if args.json_output:
        save_json_output(results, args.json_output)

def print_summary(results: Dict[str, Any]):
    """Prints a high-level summary of the scan results to the console."""
    if "headers" in results and results["headers"]:
        status = results["headers"].get('status_code', 'N/A')
        server = results["headers"].get('server_info', {}).get('server', 'N/A')
        print(f"  - {Fore.CYAN}HTTP Status:{Style.RESET_ALL} {Fore.YELLOW}{status}{Style.RESET_ALL}, {Fore.CYAN}Server:{Style.RESET_ALL} {Fore.YELLOW}{server}{Style.RESET_ALL}")

    if "ssl_certificate" in results and results["ssl_certificate"]:
        if "error" in results["ssl_certificate"]:
            print(f"  - {Fore.CYAN}SSL Status:{Style.RESET_ALL} {Fore.RED}{results['ssl_certificate']['error']}{Style.RESET_ALL}")
        else:
            expiry = results["ssl_certificate"].get('valid_until', 'N/A')
            expired = results["ssl_certificate"].get('has_expired', True)
            match = results["ssl_certificate"].get('domain_match', False)
            expired_color = Fore.RED if expired else Fore.GREEN
            match_color = Fore.GREEN if match else Fore.RED
            print(f"  - {Fore.CYAN}SSL Certificate:{Style.RESET_ALL} Expires on {Fore.YELLOW}{expiry}{Style.RESET_ALL} (Expired: {expired_color}{expired}{Style.RESET_ALL}, Domain Match: {match_color}{match}{Style.RESET_ALL})")

    if "crawl" in results and results["crawl"]:
        robots = results["crawl"].get("robots_txt", {})
        sitemap = results["crawl"].get("sitemap", {})
        robots_found = 'Found' if robots.get('exists') else 'Not Found'
        robots_color = Fore.YELLOW if robots.get('exists') else Fore.GREEN
        print(f"  - {Fore.CYAN}Robots.txt:{Style.RESET_ALL} {robots_color}{robots_found}{Style.RESET_ALL}, {Fore.CYAN}Sitemap URLs:{Style.RESET_ALL} {Fore.YELLOW}{len(sitemap.get('urls', []))}{Style.RESET_ALL}")

    if "vulnerabilities" in results and results["vulnerabilities"]:
        headers = results["vulnerabilities"].get("security_headers", {})
        sqli = results["vulnerabilities"].get("sql_injection", {})
        xss = results["vulnerabilities"].get("cross_site_scripting", {})
        
        missing_headers_count = len(headers.get('missing_headers', []))
        headers_color = Fore.RED if missing_headers_count > 0 else Fore.GREEN
        print(f"  - {Fore.CYAN}Security Headers:{Style.RESET_ALL} {headers_color}{missing_headers_count} missing{Style.RESET_ALL}")

        sqli_vuln = sqli.get('vulnerable', False)
        sqli_color = Fore.RED if sqli_vuln else Fore.GREEN
        print(f"  - {Fore.CYAN}SQL Injection:{Style.RESET_ALL} Vulnerable - {sqli_color}{sqli_vuln}{Style.RESET_ALL}")

        xss_vuln = xss.get('vulnerable', False)
        xss_color = Fore.RED if xss_vuln else Fore.GREEN
        print(f"  - {Fore.CYAN}Reflected XSS:{Style.RESET_ALL} Vulnerable - {xss_color}{xss_vuln}{Style.RESET_ALL}")


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

        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Saving full report to: {Fore.YELLOW}{full_path}{Style.RESET_ALL}")
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
            
    except (IOError, OSError) as e:
        print(f"\n{Fore.RED}[!] Error:{Style.RESET_ALL} Could not save JSON output to {path}. Reason: {e}")

def main():
    """
    Main entry point for the NodeHawk CLI.
    """
    init()
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
        print(f"{Fore.YELLOW}[!] No scan type specified. Running a default scan (headers, ssl, basic crawl).{Style.RESET_ALL}")
        args.headers = True
        args.ssl = True
        args.crawl = True

    run_scan(args)


if __name__ == "__main__":
    main()