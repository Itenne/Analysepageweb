from __future__ import annotations
import socket, time
from .models import DnsResult
def resolve(hostname: str) -> DnsResult:
    started = time.monotonic()
    try: return DnsResult("OK", sorted({e[4][0] for e in socket.getaddrinfo(hostname, None)}), round((time.monotonic()-started)*1000))
    except socket.gaierror as exc: return DnsResult("DNS_ERROR", [], round((time.monotonic()-started)*1000), str(exc))
