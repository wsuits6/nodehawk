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

        # Clean up the certificate data for JSON output
        issuer = {k.decode('utf-8'): v.decode('utf-8') for k, v in cert_info["issuer"]}
        subject = {k.decode('utf-8'): v.decode('utf-8') for k, v in cert_info["subject"]}
        
        # Parse date strings into ISO 8601 format
        not_before_str = cert_info.get('not_before', b'').decode('utf-8')
        not_after_str = cert_info.get('not_after', b'').decode('utf-8')
        
        try:
            not_before = datetime.strptime(not_before_str, '%Y%m%d%H%M%SZ').isoformat()
            not_after = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ').isoformat()
        except ValueError:
            not_before = not_before_str
            not_after = not_after_str

        # Check if domain matches certificate's Common Name or Subject Alternative Name
        domain_match = False
        if 'CN' in subject and subject['CN'] == self.domain:
            domain_match = True
        else:
            for ext in cert_info.get("extensions", []):
                if ext.get("name") == "subjectAltName":
                    # The value is a string like "DNS:*.example.com, DNS:example.com"
                    alt_names = [name.strip().replace('DNS:', '') for name in ext["value"].split(',')]
                    if any(self.domain == name or (name.startswith('*') and self.domain.endswith(name[1:])) for name in alt_names):
                        domain_match = True
                        break
        
        return {
            "issuer": issuer,
            "subject": subject,
            "valid_from": not_before,
            "valid_until": not_after,
            "has_expired": cert_info.get("has_expired", True),
            "domain_match": domain_match,
            "signature_algorithm": cert_info.get("signature_algorithm", b"unknown").decode('utf-8'),
            "serial_number": cert_info.get("serial_number")
        }

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