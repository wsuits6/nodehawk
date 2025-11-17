# examples/scan_example.py
from nodehawk.core.scanner import check_website
from nodehawk.core.crawler import crawl_website
from nodehawk.core.utils import format_url

if __name__ == "__main__":
    url = "https://example.com"
    url = format_url(url)
    check_website(url)
    crawl_website(url)
