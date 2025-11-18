# nodehawk/core/vuln_checker.py
import re
from typing import Dict, Any, List
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from nodehawk.core.utils import RequestHandler

class VulnerabilityChecker:
    """
    Performs vulnerability checks for SQLi, XSS, and security headers.
    """
    # Basic SQLi payloads
    SQLI_PAYLOADS = ["'", '"', "' OR 1=1 --", '" OR 1=1 --', " OR 1=1 --"]
    
    # Common SQL error patterns
    SQL_ERROR_PATTERNS = [
        re.compile(r"SQL syntax.*?MySQL", re.I),
        re.compile(r"Warning.*mysqli?", re.I),
        re.compile(r"supplied argument is not a valid PostgreSQL", re.I),
        re.compile(r"Microsoft OLE DB Provider for ODBC Drivers", re.I),
        re.compile(r"Unclosed quotation mark after the character string", re.I),
        re.compile(r"you have an error in your sql syntax", re.I)
    ]

    # Basic XSS payload
    XSS_PAYLOAD = "<script>alert('NodeHawkXSS')</script>"
    
    # Recommended security headers
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    def __init__(self, url: str, request_handler: RequestHandler):
        """
        Initializes the VulnerabilityChecker.

        Args:
            url: The target URL to scan.
            request_handler: An instance of RequestHandler for making HTTP requests.
        """
        self.base_url = url
        self.request_handler = request_handler

    def check_security_headers(self) -> Dict[str, Any]:
        """
        Analyzes HTTP headers for the presence of important security headers.

        Returns:
            A dictionary detailing which security headers are present or missing.
        """
        result: Dict[str, Any] = {
            "present_headers": [],
            "missing_headers": [],
            "details": {}
        }
        response = self.request_handler.get(self.base_url)
        if not response:
            return {"error": "Could not fetch headers to analyze."}

        headers = {k.lower(): v for k, v in response.headers.items()}
        
        for header in self.SECURITY_HEADERS:
            if header.lower() in headers:
                result["present_headers"].append(header)
                result["details"][header] = headers[header.lower()]
            else:
                result["missing_headers"].append(header)
        
        return result

    def check_sql_injection(self) -> Dict[str, Any]:
        """
        Tests for basic SQL injection vulnerabilities in URL parameters.

        Returns:
            A dictionary indicating if a potential vulnerability was found.
        """
        parsed_url = urlparse(self.base_url)
        query_params = parse_qs(parsed_url.query)
        if not query_params:
            return {"vulnerable": False, "reason": "No query parameters to test."}

        vulnerable = False
        details: List[Dict[str, str]] = []

        for param in query_params:
            original_value = query_params[param][0]
            for payload in self.SQLI_PAYLOADS:
                # Create a mutable copy of query_params
                test_params = {k: v[0] for k, v in query_params.items()}
                test_params[param] = original_value + payload
                
                # Reconstruct the URL with the payload
                new_query = urlencode(test_params)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                response = self.request_handler.get(test_url)
                if response and response.text:
                    for pattern in self.SQL_ERROR_PATTERNS:
                        if pattern.search(response.text):
                            vulnerable = True
                            details.append({
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "error_pattern": pattern.pattern
                            })
                            # Stop after first detection for this parameter
                            break
                if vulnerable:
                    break
            if vulnerable:
                break
        
        return {"vulnerable": vulnerable, "details": details}

    def check_xss(self) -> Dict[str, Any]:
        """
        Tests for basic reflected Cross-Site Scripting (XSS) in URL parameters.

        Returns:
            A dictionary indicating if a potential vulnerability was found.
        """
        parsed_url = urlparse(self.base_url)
        query_params = parse_qs(parsed_url.query)
        if not query_params:
            return {"vulnerable": False, "reason": "No query parameters to test."}

        vulnerable = False
        details: List[Dict[str, str]] = []

        for param in query_params:
            original_value = query_params[param][0]
            
            # Create a mutable copy of query_params
            test_params = {k: v[0] for k, v in query_params.items()}
            test_params[param] = self.XSS_PAYLOAD
            
            # Reconstruct the URL with the payload
            new_query = urlencode(test_params, safe='<>') # Keep payload characters
            test_url = urlunparse(parsed_url._replace(query=new_query))
            
            response = self.request_handler.get(test_url)
            
            # Check if the payload is reflected in the response body
            if response and response.text and self.XSS_PAYLOAD in response.text:
                vulnerable = True
                details.append({
                    "url": test_url,
                    "parameter": param,
                    "payload": self.XSS_PAYLOAD
                })
                break # Stop after first detection
        
        return {"vulnerable": vulnerable, "details": details}

    def run_all_checks(self) -> Dict[str, Any]:
        """
        Runs all vulnerability checks.

        Returns:
            A dictionary containing the results of all vulnerability scans.
        """
        results = {
            "security_headers": self.check_security_headers(),
            "sql_injection": self.check_sql_injection(),
            "cross_site_scripting": self.check_xss()
        }
        return results