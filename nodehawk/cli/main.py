# nodehawk/cli/main.py

from nodehawk.core.scanner import WebsiteScanner
from nodehawk.core.crawler import WebsiteCrawler
from nodehawk.core.vuln_checker import VulnerabilityChecker
from nodehawk.core.utils import format_url


def main():
    print("=== NodeHawk Web Scanner ===")
    url = format_url(input("Enter website URL to scan: ").strip())

    scanner = WebsiteScanner(url)
    crawler = WebsiteCrawler(url)
    vulns = VulnerabilityChecker(url)

    print("\n--- Website Status ---")
    scanner.check_status()

    print("\n--- Crawling ---")
    crawler.crawl()

    print("\n--- Headers ---")
    scanner.fetch_headers()
    scanner.get_server_info()

    print("\n--- Vulnerability Checks ---")
    vulns.run_basic_checks()


if __name__ == "__main__":
    main()
