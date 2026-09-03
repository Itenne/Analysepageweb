"""Serializable models used by test and report runs."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
@dataclass
class DnsResult:
    status: str = "NOT_RUN"
    addresses: list[str] = field(default_factory=list)
    duration_ms: Optional[int] = None
    error: str = ""
@dataclass
class TestResult:
    url: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    public_ip: str = ""
    hostname: str = ""
    dns: DnsResult = field(default_factory=DnsResult)
    final_url: str = ""
    method: str = "GET"
    http_status: Optional[int] = None
    duration_ms: Optional[int] = None
    redirects: list[str] = field(default_factory=list)
    remote_ip: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    page_title: str = ""
    page_html: str = ""
    classification: str = "UNKNOWN"
    confidence: str = "UNKNOWN"
    reason: str = ""
    indicators: list[str] = field(default_factory=list)
    error: str = ""
    def to_dict(self) -> dict:
        data = asdict(self); data["dns"] = asdict(self.dns); return data
