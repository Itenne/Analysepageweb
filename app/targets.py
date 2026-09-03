"""Helpers for identifying a URL's DNS target within a test run."""
from __future__ import annotations

from urllib.parse import urlparse


def fqdn_for_url(url: str) -> str:
    """Return the normalized FQDN from an absolute URL, or an empty string."""
    return (urlparse(url.strip()).hostname or "").rstrip(".").lower()


def unique_urls_by_fqdn(urls: list[str]) -> list[str]:
    """Keep the first URL for every FQDN while preserving input order.

    Invalid URLs have no FQDN, so they are retained and can be reported by the
    normal URL validation path rather than silently disappearing.
    """
    seen_fqdns: set[str] = set()
    unique: list[str] = []
    for url in urls:
        fqdn = fqdn_for_url(url)
        if not fqdn or fqdn not in seen_fqdns:
            unique.append(url)
            if fqdn:
                seen_fqdns.add(fqdn)
    return unique
