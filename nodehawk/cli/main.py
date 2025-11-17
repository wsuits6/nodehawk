# nodehawk/cli/main.py
from nodehawk.core.scanner import check_website
from nodehawk.core.crawler import crawl_website
from nodehawk.core.vuln_checker import basic_check
from nodehawk.core.utils import format_url

def main():
    print("=== NodeHawk Web Scanner ===")
    url = input("Enter website URL to scan: ").strip()
    url = format_url(url)

    check_website(url)
    crawl_website(url)
    basic_check(url)

if __name__ == "__main__":
    main()
