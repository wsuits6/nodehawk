# nodehawk/core/crawler.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class WebsiteCrawler:
    """Extracts hyperlinks and crawls website pages."""

    def __init__(self, url: str):
        self.url = url
        self.found_links = set()

    def crawl(self, max_links=20):
        """Collects hyperlinks from a page."""
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            for a in soup.find_all("a", href=True):
                full = urljoin(self.url, a["href"])
                self.found_links.add(full)

                if len(self.found_links) >= max_links:
                    break

            print(f"\n[+] Found {len(self.found_links)} links on {self.url}:")
            for link in self.found_links:
                print(f"  - {link}")

            return self.found_links

        except requests.exceptions.RequestException as e:
            print(f"[-] Could not crawl {self.url}. Error: {e}")
            return set()
