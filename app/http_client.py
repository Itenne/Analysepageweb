from __future__ import annotations
import re, socket, time, logging
from urllib.parse import urlparse
import requests
from requests import exceptions
from .models import TestResult
from .dns_checker import resolve
from .security import validate_url, UrlValidationError
from .classifier import classify
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
class WebTester:
    def __init__(self, signatures: dict, connect_timeout=10, total_timeout=20, use_system_proxy=True, user_agent="SASE-Web-Validation-Tool/0.1.0"):
        self.signatures, self.connect_timeout, self.total_timeout = signatures, connect_timeout, total_timeout
        self.session = requests.Session(); self.session.trust_env = use_system_proxy; self.user_agent = user_agent
    def test(self, url: str, public_ip="") -> TestResult:
        result = TestResult(url=url, public_ip=public_ip)
        logging.info("Starting test url=%s", url)
        try: validate_url(url)
        except UrlValidationError as exc: result.classification="CONNECTION_ERROR"; result.reason="URL rejected by local safety policy."; result.error=str(exc); return result
        result.hostname = urlparse(url).hostname or ""; result.dns = resolve(result.hostname)
        if result.dns.status != "OK": result.classification="DNS_ERROR"; result.reason="Hostname could not be resolved."; result.error=result.dns.error; return result
        started=time.monotonic()
        try:
            response=self.session.get(url, headers={"User-Agent":self.user_agent, "Accept":"text/html,application/xhtml+xml"}, timeout=(self.connect_timeout,self.total_timeout), allow_redirects=True, stream=True)
            content=next(response.iter_content(65536), b"").decode(response.encoding or "utf-8", errors="replace")
            result.final_url=response.url; result.http_status=response.status_code; result.duration_ms=round((time.monotonic()-started)*1000)
            result.redirects=[r.url for r in response.history]; result.headers={k:v[:500] for k,v in response.headers.items() if k.lower() in {"server","via","location","content-type","www-authenticate","proxy-authenticate","x-squid-error","x-bluecoat-via","x-zscaler","x-cisco-umbrella"}}
            match=TITLE.search(content); result.page_title=(match.group(1).strip() if match else "")[:500]
            # classifier receives bounded title plus selected headers; do not persist full page.
            result.headers["X-Analysis-Snippet"] = re.sub(r"<[^>]+>", " ", content)[:8192]
            try: result.remote_ip=socket.gethostbyname(urlparse(response.url).hostname or result.hostname)
            except socket.gaierror: pass
            classify(result,self.signatures); result.headers.pop("X-Analysis-Snippet",None); response.close(); logging.info("Finished test url=%s classification=%s status=%s", url, result.classification, result.http_status); return result
        except exceptions.TooManyRedirects as exc: result.classification="REDIRECT_ERROR"; result.error=str(exc)
        except (exceptions.ConnectTimeout, exceptions.ReadTimeout, exceptions.Timeout) as exc: result.classification="TIMEOUT"; result.error=str(exc)
        except exceptions.SSLError as exc: result.classification="TLS_ERROR"; result.error=str(exc)
        except exceptions.ProxyError as exc: result.classification="PROXY_ERROR"; result.error=str(exc)
        except exceptions.ConnectionError as exc: result.classification="CONNECTION_ERROR"; result.error=str(exc)
        except exceptions.RequestException as exc: result.classification="UNKNOWN"; result.error=str(exc)
        result.duration_ms=round((time.monotonic()-started)*1000); logging.warning("Test failed url=%s classification=%s", url, result.classification); result.reason="Request failed before an HTTP response was available."; return result
