# nodehawk/core/scanner.py
import requests
from colorama import Fore, Style

def check_website(url: str):
    """Check if a website is online and return status code"""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"{Fore.GREEN}[+] {url} is online! Status: {response.status_code}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] {url} returned status code: {response.status_code}{Style.RESET_ALL}")
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Could not reach {url}. Error: {e}{Style.RESET_ALL}")
        return None

if __name__ == "__main__":
    url = input("Enter website URL to scan: ")
    check_website(url)
