# nodehawk/core/crawler.py
import re
from typing import Dict, Any, Set, List, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings

from nodehawk.core.utils import RequestHandler

# Suppress the XMLParsedAsHTMLWarning that BeautifulSoup may throw on malformed sitemaps
warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)

class Crawler:
    """
    Handles crawling, robots.txt parsing, and sitemap analysis.
    """
    def __init__(self, url: str, request_handler: RequestHandler):
        """
        Initializes the Crawler.

        Args:
            url: The base URL to start crawling from.
            request_handler: An instance of RequestHandler for making HTTP requests.
        """
        self.base_url = url
        self.domain = urlparse(url).netloc
        self.request_handler = request_handler
        self.sitemap_urls: Set[str] = set()

    def scan_robots_txt(self) -> Dict[str, Any]:
        """
        Fetches and parses the robots.txt file.

        Returns:
            A dictionary containing disallowed paths and sitemap locations.
        """
        robots_url = urljoin(self.base_url, "/robots.txt")
        result: Dict[str, Any] = {
            "url": robots_url,
            "exists": False,
            "disallowed_paths": [],
            "sitemap_urls": []
        }
        
        response = self.request_handler.get(robots_url)
        if response and response.status_code == 200:
            result["exists"] = True
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallowed_paths"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    result["sitemap_urls"].append(sitemap_url)
                    self.sitemap_urls.add(sitemap_url)
        
        return result

    def scan_sitemap(self) -> Dict[str, Any]:
        """
        Finds and parses sitemap.xml files.

        It first checks robots.txt, then falls back to a common location.

        Returns:
            A dictionary containing all URLs found in the sitemap(s).
        """
        result: Dict[str, Any] = {
            "sitemaps_found": list(self.sitemap_urls),
            "urls": []
        }
        
        # If robots.txt didn't give us a sitemap, check the default location
        if not self.sitemap_urls:
            default_sitemap_url = urljoin(self.base_url, "/sitemap.xml")
            # Check if it exists before adding
            response = self.request_handler.get(default_sitemap_url, allow_redirects=True)
            if response and response.status_code == 200:
                self.sitemap_urls.add(response.url) # Use final URL after redirects
                result["sitemaps_found"].append(response.url)

        sitemaps_to_parse = set(self.sitemap_urls)
        parsed_sitemaps = set()

        while sitemaps_to_parse:
            sitemap_url = sitemaps_to_parse.pop()
            if sitemap_url in parsed_sitemaps:
                continue

            response = self.request_handler.get(sitemap_url)
            parsed_sitemaps.add(sitemap_url)

            if response:
                # Using 'lxml-xml' for robustness with XML files
                soup = BeautifulSoup(response.content, "lxml-xml")
                
                # Check for sitemap index files
                sitemap_tags = soup.find_all("sitemap")
                if sitemap_tags:
                    for tag in sitemap_tags:
                        loc = tag.find("loc")
                        if loc and loc.text:
                            sitemaps_to_parse.add(loc.text.strip())
                    continue # Move to the next sitemap in the queue

                # Find all <loc> tags which contain the URLs
                loc_tags = soup.find_all("loc")
                for loc in loc_tags:
                    if loc.text:
                        result["urls"].append(loc.text.strip())
        
        # Deduplicate URLs
        result["urls"] = sorted(list(set(result["urls"])))
        return result

    def crawl_page(self, url: str, max_links: int = 20) -> Set[str]:
        """
        Crawls a single page to find links.

        Args:
            url: The URL of the page to crawl.
            max_links: The maximum number of unique links to return.

        Returns:
            A set of unique, absolute URLs found on the page.
        """
        found_links: Set[str] = set()
        response = self.request_handler.get(url)
        if not response:
            return found_links

        soup = BeautifulSoup(response.text, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag['href']
            if not href or href.startswith(('mailto:', 'tel:')):
                continue
            
            full_url = urljoin(self.base_url, href)
            
            # Only add links that are within the same domain
            if urlparse(full_url).netloc == self.domain:
                found_links.add(full_url)
                if len(found_links) >= max_links:
                    break
        
        return found_links

    def run_crawl(self, deep: bool = False, max_links_per_page: int = 20) -> Dict[str, Any]:
        """
        Runs the crawl, optionally performing a deep crawl using sitemap URLs.

        Args:
            deep: If True, uses sitemap URLs for crawling. Otherwise, just crawls the base URL.
            max_links_per_page: The max links to extract from any single page.

        Returns:
            A dictionary containing all crawl-related findings.
        """
        robots_info = self.scan_robots_txt()
        sitemap_info = self.scan_sitemap()

        crawled_links: Dict[str, List[str]] = {}

        if deep:
            urls_to_crawl = sitemap_info.get("urls", [])
            # Limit deep crawl to a reasonable number to avoid excessive requests
            if len(urls_to_crawl) > 50:
                urls_to_crawl = urls_to_crawl[:50]
        else:
            urls_to_crawl = [self.base_url]

        for url in urls_to_crawl:
            links = self.crawl_page(url, max_links=max_links_per_page)
            crawled_links[url] = sorted(list(links))

        return {
            "robots_txt": robots_info,
            "sitemap": sitemap_info,
            "crawled_pages": crawled_links
        }