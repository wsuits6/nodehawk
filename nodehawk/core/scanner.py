# nodehawk/core/scanner.py
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from nodehawk.core.utils import RequestHandler, get_server_certificate, get_domain_from_url

class Scanner:
    """
    Performs scanning tasks like header analysis and SSL certificate inspection.
    """
    def __init__(self, url: str, request_handler: RequestHandler):
        """
        Initializes the Scanner.

        Args:
            url: The target URL to scan.
            request_handler: An instance of RequestHandler for making HTTP requests.
        """
        self.url = url
        self.domain = get_domain_from_url(url)
        self.request_handler = request_handler

    def scan_headers(self) -> Dict[str, Any]:
        """
        Fetches and analyzes HTTP headers.

        Returns:
            A dictionary containing the headers and server information.
        """
        result: Dict[str, Any] = {
            "status_code": None,
            "headers": {},
            "server_info": {
                "server": "Unknown",
                "x_powered_by": "Unknown"
            }
        }
        
        # Use get_without_verification to ensure we can get headers even if SSL cert is bad
        response = self.request_handler.get_without_verification(self.url)
        
        if response:
            result["status_code"] = response.status_code
            result["headers"] = dict(response.headers)
            result["server_info"]["server"] = response.headers.get("Server", "Unknown")
            result["server_info"]["x_powered_by"] = response.headers.get("X-Powered-By", "Unknown")
            
        return result

    def scan_ssl(self) -> Optional[Dict[str, Any]]:
        """
        Performs SSL certificate inspection.

        Returns:
            A dictionary with SSL certificate details, or None if not an HTTPS site.
        """
        if not self.url.startswith("https://"):
            return None

        cert_info = get_server_certificate(self.domain)
        if not cert_info:
            return {
                "error": "Failed to retrieve SSL certificate."
            }

        # Date parsing
        try:
            valid_from = datetime.strptime(cert_info['not_before'], '%Y%m%d%H%M%SZ').isoformat()
            valid_until = datetime.strptime(cert_info['not_after'], '%Y%m%d%H%M%SZ').isoformat()
        except (ValueError, KeyError):
            valid_from = cert_info.get('not_before')
            valid_until = cert_info.get('not_after')

        # Domain matching
        domain_match = False
        subject = cert_info.get("subject", {})
        if subject.get('CN') == self.domain:
            domain_match = True
        else:
            for ext in cert_info.get("extensions", []):
                if ext.get("name") == "subjectAltName":
                    alt_names = [name.strip().replace('DNS:', '') for name in ext.get("value", "").split(',')]
                    if any(self.domain == name or (name.startswith('*') and self.domain.endswith(name[1:])) for name in alt_names):
                        domain_match = True
                        break
        
        # Prepare final report, keeping all original fields and adding processed ones
        report = cert_info.copy()
        report.update({
            "valid_from": valid_from,
            "valid_until": valid_until,
            "domain_match": domain_match
        })

        return report

    def run_full_scan(self) -> Dict[str, Any]:
        """
        Runs all available scans in the Scanner module.

        Returns:
            A dictionary containing all scan results.
        """
        results = {
            "http_headers": self.scan_headers(),
            "ssl_certificate": self.scan_ssl()
        }
        return results