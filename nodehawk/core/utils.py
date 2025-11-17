# nodehawk/core/utils.py
def format_url(url: str) -> str:
    """Ensure URL has http:// or https://"""
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url
