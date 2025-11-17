# nodehawk/core/crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl_website(url: str, max_links=20):
    """Crawl a website and extract up to max_links links"""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        links = set()
        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag['href'])
            links.add(full_url)
            if len(links) >= max_links:
                break
        print(f"[+] Found {len(links)} links on {url}:")
        for link in links:
            print(f"  - {link}")
        return links
    except requests.exceptions.RequestException as e:
        print(f"[-] Could not crawl {url}. Error: {e}")
        return set()

if __name__ == "__main__":
    url = input("Enter website URL to crawl: ")
    crawl_website(url)
