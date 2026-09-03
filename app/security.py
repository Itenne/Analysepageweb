"""Input validation: only public HTTP(S) destinations are testable."""
from __future__ import annotations
import ipaddress, socket
from urllib.parse import urlparse
class UrlValidationError(ValueError): pass
def validate_url(value: str) -> str:
    value = value.strip(); parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname: raise UrlValidationError("URL must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password: raise UrlValidationError("URLs with credentials are not allowed")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"): raise UrlValidationError("Local destinations are not allowed")
    try: addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror: return value
    for address in addresses:
        if not ipaddress.ip_address(address).is_global: raise UrlValidationError("Private, loopback, link-local, or reserved destinations are not allowed")
    return value
