from __future__ import annotations
import logging
import re
import threading
import time
import requests
from requests import exceptions
from .models import TestResult
from .dns_checker import resolve
from .security import validate_url, UrlValidationError
from .classifier import classify
from .targets import fqdn_for_url
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
class WebTester:
    def __init__(self, signatures: dict, connect_timeout=10, total_timeout=20, use_system_proxy=True, user_agent="SASE-Web-Validation-Tool/0.1.0"):
        self.signatures, self.connect_timeout, self.total_timeout = signatures, connect_timeout, total_timeout
        self.session = requests.Session(); self.session.trust_env = use_system_proxy; self.user_agent = user_agent
        self._dns_cache = {}
        self._dns_lock = threading.Lock()

    def clear_dns_cache(self) -> None:
        """Start a fresh run without carrying DNS observations forward."""
        with self._dns_lock:
            self._dns_cache.clear()

    def _resolve_fqdn(self, fqdn: str):
        """Resolve each FQDN once, including when workers start concurrently."""
        with self._dns_lock:
            cached = self._dns_cache.get(fqdn)
            if cached is None:
                cached = resolve(fqdn)
                self._dns_cache[fqdn] = cached
            return cached

    def test(self, url: str, public_ip="") -> TestResult:
        result = TestResult(url=url, public_ip=public_ip)
        logging.info("Starting test url=%s", url)
        try: validate_url(url, resolved_addresses=[])
        except UrlValidationError as exc: result.classification="CONNECTION_ERROR"; result.reason="URL rejected by local safety policy."; result.error=str(exc); return result
        result.hostname = fqdn_for_url(url)
        result.dns = self._resolve_fqdn(result.hostname)
        if result.dns.status != "OK": result.classification="DNS_ERROR"; result.reason="Hostname could not be resolved."; result.error=result.dns.error; return result
        try: validate_url(url, resolved_addresses=result.dns.addresses)
        except UrlValidationError as exc: result.classification="CONNECTION_ERROR"; result.reason="URL rejected by local safety policy."; result.error=str(exc); return result
        started=time.monotonic()
        try:
            response=self.session.get(url, headers={"User-Agent":self.user_agent, "Accept":"text/html,application/xhtml+xml"}, timeout=(self.connect_timeout,self.total_timeout), allow_redirects=True, stream=True)
            content=next(response.iter_content(65536), b"").decode(response.encoding or "utf-8", errors="replace")
            result.final_url=response.url; result.http_status=response.status_code; result.duration_ms=round((time.monotonic()-started)*1000)
            result.redirects=[r.url for r in response.history]; result.headers={k:v[:500] for k,v in response.headers.items() if k.lower() in {"server","via","location","content-type","www-authenticate","proxy-authenticate","x-squid-error","x-bluecoat-via","x-zscaler","x-cisco-umbrella"}}
            match=TITLE.search(content); result.page_title=(match.group(1).strip() if match else "")[:500]
            # classifier receives bounded title plus selected headers; do not persist full page.
            result.headers["X-Analysis-Snippet"] = re.sub(r"<[^>]+>", " ", content)[:8192]
            # Reuse the DNS answer already recorded for the target FQDN.  A
            # redirected destination is intentionally not resolved separately.
            if fqdn_for_url(response.url) == result.hostname:
                result.remote_ip = result.dns.addresses[0]
            classify(result,self.signatures); result.headers.pop("X-Analysis-Snippet",None); response.close(); logging.info("Finished test url=%s classification=%s status=%s", url, result.classification, result.http_status); return result
        except exceptions.TooManyRedirects as exc: result.classification="REDIRECT_ERROR"; result.error=str(exc)
        except (exceptions.ConnectTimeout, exceptions.ReadTimeout, exceptions.Timeout) as exc: result.classification="TIMEOUT"; result.error=str(exc)
        except exceptions.SSLError as exc: result.classification="TLS_ERROR"; result.error=str(exc)
        except exceptions.ProxyError as exc: result.classification="PROXY_ERROR"; result.error=str(exc)
        except exceptions.ConnectionError as exc: result.classification="CONNECTION_ERROR"; result.error=str(exc)
        except exceptions.RequestException as exc: result.classification="UNKNOWN"; result.error=str(exc)
        result.duration_ms=round((time.monotonic()-started)*1000); logging.warning("Test failed url=%s classification=%s", url, result.classification); result.reason="Request failed before an HTTP response was available."; return result
