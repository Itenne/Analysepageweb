from __future__ import annotations
from datetime import datetime, timezone
import requests
ENDPOINTS=["https://api.ipify.org?format=json", "https://ifconfig.me/ip"]
def detect_public_ip(endpoints=ENDPOINTS, timeout=10, use_system_proxy=True) -> dict:
    session=requests.Session(); session.trust_env=use_system_proxy; observations=[]
    for endpoint in endpoints:
        try:
            value=session.get(endpoint, timeout=timeout, headers={"User-Agent":"SASE-Web-Validation-Tool/0.1.0"}).json().get("ip") if "json" in endpoint else session.get(endpoint, timeout=timeout).text.strip()
            if value: observations.append({"endpoint":endpoint,"ip":value})
        except requests.RequestException: continue
    values={x["ip"] for x in observations}
    return {"ip": next(iter(values), ""), "confidence": "HIGH" if len(values)==1 and len(observations)>=2 else ("LOW" if values else "UNKNOWN"), "observations":observations, "timestamp":datetime.now(timezone.utc).isoformat()}
