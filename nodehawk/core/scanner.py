# nodehawk/core/scanner.py

import requests
from colorama import Fore, Style
from urllib.parse import urlparse


class WebsiteScanner:
    """Handles status checking, header collection, and SSL details."""

    def __init__(self, url: str):
        self.url = url
        self.response = None

    def check_status(self):
        """Check if website is reachable."""
        try:
            self.response = requests.get(self.url, timeout=5)
            code = self.response.status_code

            if code == 200:
                print(f"{Fore.GREEN}[+] {self.url} is online! Status: {code}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] {self.url} returned status code: {code}{Style.RESET_ALL}")

            return code

        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Could not reach {self.url}. Error: {e}{Style.RESET_ALL}")
            return None

    def fetch_headers(self):
        """Fetch HTTP headers."""
        if not self.response:
            try:
                self.response = requests.get(self.url, timeout=5)
            except Exception as e:
                print(f"{Fore.RED}[-] Cannot fetch headers: {e}{Style.RESET_ALL}")
                return None

        print(f"\n{Fore.CYAN}[+] Headers for {self.url}:{Style.RESET_ALL}")
        for key, value in self.response.headers.items():
            print(f"  {key}: {value}")

        return self.response.headers

    def get_server_info(self):
        """Extract server info (Server header, tech stack hints)."""
        headers = self.response.headers if self.response else None
        if not headers:
            return None

        server = headers.get("Server", "Unknown")
        powered_by = headers.get("X-Powered-By", "Unknown")

        print(f"\n{Fore.MAGENTA}[*] Server: {server}")
        print(f"[*] Powered By: {powered_by}{Style.RESET_ALL}")

        return {"server": server, "powered_by": powered_by}
