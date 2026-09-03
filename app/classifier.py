from __future__ import annotations
from .models import TestResult

def classify(result: TestResult, signatures: dict) -> TestResult:
    text = " ".join([result.final_url, result.page_title, " ".join(result.headers.values())]).lower()
    # Only diagnostic snippets are supplied; full response bodies are never retained.
    ip_hits = [s for s in signatures["ip_restriction"] if s.lower() in text]
    block_hits = [s for s in signatures["blocking"] if s.lower() in text]
    authentication_hits = [s for s in signatures.get("authentication", []) if s.lower() in text]
    proxy_hit = any(header in {k.lower() for k in result.headers} for header in signatures.get("proxy_headers", []))
    if ip_hits:
        result.classification = "IP_RESTRICTION"; result.confidence = "HIGH" if result.http_status in {401, 403, 451} and len(ip_hits) >= 1 else "MEDIUM"
        result.reason = "Response content indicates a possible source IP restriction; this is an indication, not proof."; result.indicators = ip_hits; return result
    if authentication_hits or result.http_status in {401, 407}:
        result.classification = "AUTHENTICATION_REQUIRED"
        result.confidence = "HIGH" if result.http_status in {401, 407} else "MEDIUM"
        result.reason = "Authentication page indicators were detected; credentials were not submitted."
        result.indicators = authentication_hits
        return result
    if result.http_status in {401,403,407,451} and (len(block_hits) >= 2 or (block_hits and proxy_hit)):
        result.classification = "ACCESS_DENIED"; result.confidence = "HIGH" if len(block_hits) >= 2 else "MEDIUM"
        result.reason = "Web filtering policy page indicators were detected."; result.indicators = block_hits; return result
    if result.http_status and 200 <= result.http_status < 400:
        result.classification = "ACCESS_ALLOWED"; result.confidence = "HIGH"; result.reason = "HTTP request completed successfully."
    elif result.http_status:
        result.classification = f"HTTP_{result.http_status}" if result.http_status in {400,401,403,407,429,451,500,502,503,504} else "UNKNOWN"
        result.confidence = "UNKNOWN"; result.reason = "HTTP response received without sufficient blocking-page evidence."
    return result
