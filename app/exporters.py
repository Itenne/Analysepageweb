from __future__ import annotations
import csv, html
from collections import Counter
from pathlib import Path
from .models import TestResult
FIELDS=["timestamp","url","final_url","public_ip","dns_status","resolved_ip","http_status","duration_ms","classification","confidence","reason","detected_indicators","error"]
def export_csv(results: list[TestResult], path: str | Path) -> None:
    with Path(path).open("w",encoding="utf-8",newline="") as out:
        writer=csv.DictWriter(out,fieldnames=FIELDS); writer.writeheader()
        for r in results: writer.writerow({"timestamp":r.timestamp,"url":r.url,"final_url":r.final_url,"public_ip":r.public_ip,"dns_status":r.dns.status,"resolved_ip":"|".join(r.dns.addresses),"http_status":r.http_status or "","duration_ms":r.duration_ms or "","classification":r.classification,"confidence":r.confidence,"reason":r.reason,"detected_indicators":" | ".join(r.indicators),"error":r.error})
def export_html(results: list[TestResult], path: str | Path, public_ip_info: dict | None=None) -> None:
    counts=Counter(r.classification for r in results); blocked=sum(1 for r in results if r.classification=="ACCESS_DENIED"); errors=sum(1 for r in results if r.classification.endswith("ERROR") or r.classification in {"TIMEOUT","TLS_ERROR","CONNECTION_ERROR","PROXY_ERROR"})
    rows="".join(f"<tr><td>{html.escape(r.url)}</td><td>{r.http_status or ''}</td><td>{html.escape(r.final_url)}</td><td>{html.escape(r.classification)}</td><td>{html.escape(r.confidence)}</td><td>{html.escape(r.reason)}</td></tr>" for r in results)
    ip=(public_ip_info or {}).get("ip", "Not detected")
    body=f"""<!doctype html><html><head><meta charset='utf-8'><title>SASE validation report</title><style>body{{font-family:Segoe UI,Arial;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.5rem;text-align:left}}th{{background:#eee}}</style></head><body><h1>SASE Web Filtering Validation Tool</h1><h2>Test Summary</h2><ul><li>Total URLs: {len(results)}</li><li>Accessible: {counts['ACCESS_ALLOWED']}</li><li>Blocked: {blocked}</li><li>IP restriction detected: {counts['IP_RESTRICTION']}</li><li>Network errors: {errors}</li><li>Unknown: {counts['UNKNOWN']}</li><li>Public IP: {html.escape(ip)}</li></ul><p>ACCESS_DENIED and IP_RESTRICTION are indicators based on observed responses, not definitive proof.</p><table><tr><th>URL</th><th>HTTP</th><th>Final URL</th><th>Classification</th><th>Confidence</th><th>Reason</th></tr>{rows}</table></body></html>"""
    Path(path).write_text(body,encoding="utf-8")
