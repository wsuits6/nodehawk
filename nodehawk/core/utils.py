# nodehawk/core/utils.py
import socket
import ssl
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import requests
from OpenSSL import SSL
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.poolmanager import PoolManager

# Suppress only the single InsecureRequestWarning from urllib3 needed for SSL inspection
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class SSLAdapter(HTTPAdapter):
    """An HTTPAdapter that can be configured with a custom SSL context."""
    def __init__(self, ssl_context: ssl.Context = None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context
        )

def get_ssl_context() -> ssl.Context:
    """Creates and returns an SSL context that trusts default CAs."""
    context = ssl.create_default_context()
    return context

def get_domain_from_url(url: str) -> str:
    """Extracts the domain name from a URL."""
    parsed_url = urlparse(url)
    return parsed_url.hostname

def format_url(url: str) -> str:
    """Ensure URL has http:// or https:// and removes trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # Default to HTTPS for security scanning
    return url.rstrip('/')

class RequestHandler:
    """A class to handle HTTP requests with a persistent session."""
    def __init__(self, headers: Optional[Dict[str, str]] = None):
        self.session = requests.Session()
        self.session.headers.update(headers or {
            "User-Agent": "NodeHawk/1.0 (Security Scanner; +https://github.com/your-repo/NodeHawk)"
        })
        
        # Mount the SSLAdapter to handle custom SSL contexts if needed
        # For now, we use the default requests behavior which verifies certs
        self.session.mount('https://', HTTPAdapter())

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Performs a GET request.
        
        Args:
            url: The URL to request.
            **kwargs: Additional arguments to pass to requests.get().

        Returns:
            A requests.Response object, or None if the request fails.
        """
        try:
            # Default to verify=True for security
            kwargs.setdefault('verify', True)
            kwargs.setdefault('timeout', 10) # Add a timeout
            response = self.session.get(url, **kwargs)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response
        except requests.exceptions.RequestException as e:
            print(f"[Error] Request to {url} failed: {e}")
            return None

    def get_without_verification(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Performs a GET request without SSL certificate verification.
        
        This is useful for initial connections to hosts with self-signed or expired certs,
        allowing the SSL inspection module to still analyze the certificate.
        """
        try:
            kwargs['verify'] = False
            kwargs.setdefault('timeout', 10)
            response = self.session.get(url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"[Error] Request to {url} (no-verify) failed: {e}")
            return None

def get_server_certificate(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """
    Retrieves and returns the SSL certificate from a server.
    
    Args:
        hostname: The hostname of the server.
        port: The port to connect to (default is 443).

    Returns:
        A dictionary containing the certificate details, or None on failure.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return None
                
                # Convert from DER to PEM for pyOpenSSL
                x509 = SSL.load_certificate(SSL.FILETYPE_ASN1, cert_der)
                return {
                    "issuer": dict(x509.get_issuer().get_components()),
                    "subject": dict(x509.get_subject().get_components()),
                    "serial_number": x509.get_serial_number(),
                    "version": x509.get_version(),
                    "not_before": x509.get_notBefore(),
                    "not_after": x509.get_notAfter(),
                    "has_expired": x509.has_expired(),
                    "signature_algorithm": x509.get_signature_algorithm(),
                    "extensions": [
                        {
                            "name": x509.get_extension(i).get_short_name().decode('utf-8'),
                            "value": str(x509.get_extension(i))
                        }
                        for i in range(x509.get_extension_count())
                    ]
                }
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
        print(f"[Error] Could not connect to {hostname}:{port} for SSL check: {e}")
        return None
    except Exception as e:
        print(f"[Error] An unexpected error occurred during SSL check for {hostname}: {e}")
        return None