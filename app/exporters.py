from __future__ import annotations
import csv, html
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile
from .models import TestResult
FIELDS=["timestamp","url","final_url","public_ip","dns_status","resolved_ip","http_status","duration_ms","classification","confidence","reason","detected_indicators","page_html","error"]

def result_row(result: TestResult) -> dict:
    return {"timestamp":result.timestamp,"url":result.url,"final_url":result.final_url,"public_ip":result.public_ip,"dns_status":result.dns.status,"resolved_ip":"|".join(result.dns.addresses),"http_status":result.http_status or "","duration_ms":result.duration_ms or "","classification":result.classification,"confidence":result.confidence,"reason":result.reason,"detected_indicators":" | ".join(result.indicators),"page_html":result.page_html,"error":result.error}

def export_csv(results: list[TestResult], path: str | Path) -> None:
    with Path(path).open("w",encoding="utf-8",newline="") as out:
        writer=csv.DictWriter(out,fieldnames=FIELDS); writer.writeheader()
        for result in results: writer.writerow(result_row(result))

def export_excel(results: list[TestResult], path: str | Path, public_ip_info: dict | None = None) -> None:
    """Write a dependency-free XLSX workbook with a summary and detailed results."""
    counts = Counter(result.classification for result in results)
    summary_rows = [
        ("SASE Web Filtering Validation Tool", ""),
        ("Metric", "Value"),
        ("Total URLs", len(results)),
        ("Accessible", counts["ACCESS_ALLOWED"]),
        ("Blocked", counts["ACCESS_DENIED"]),
        ("Authentication required", counts["AUTHENTICATION_REQUIRED"]),
        ("IP restriction detected", counts["IP_RESTRICTION"]),
        ("Public IP", (public_ip_info or {}).get("ip", "Not detected")),
    ]
    detail_rows = [FIELDS] + [[result_row(result)[field] for field in FIELDS] for result in results]
    with ZipFile(Path(path), "w", ZIP_DEFLATED) as workbook:
        workbook.writestr("[Content_Types].xml", """<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>""")
        workbook.writestr("_rels/.rels", """<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>""")
        workbook.writestr("xl/workbook.xml", """<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"Summary\" sheetId=\"1\" r:id=\"rId1\"/><sheet name=\"Results\" sheetId=\"2\" r:id=\"rId2\"/></sheets></workbook>""")
        workbook.writestr("xl/_rels/workbook.xml.rels", """<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet2.xml\"/></Relationships>""")
        workbook.writestr("xl/worksheets/sheet1.xml", _worksheet_xml(summary_rows))
        workbook.writestr("xl/worksheets/sheet2.xml", _worksheet_xml(detail_rows, has_filter=True))

def _worksheet_xml(rows: list[list | tuple], has_filter: bool = False) -> str:
    def column_name(index: int) -> str:
        name = ""
        while index:
            index, remainder = divmod(index - 1, 26)
            name = chr(65 + remainder) + name
        return name
    xml_rows = []
    for row_index, row in enumerate(rows, 1):
        cells = "".join(f'<c r="{column_name(column_index)}{row_index}" t="inlineStr"><is><t>{escape(str(value if value is not None else ""))}</t></is></c>' for column_index, value in enumerate(row, 1))
        xml_rows.append(f'<row r="{row_index}">{cells}</row>')
    filter_xml = f'<autoFilter ref="A1:{column_name(len(rows[0]))}{len(rows)}"/>' if has_filter and rows else ""
    return f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{"".join(xml_rows)}</sheetData>{filter_xml}</worksheet>'
def export_html(results: list[TestResult], path: str | Path, public_ip_info: dict | None=None) -> None:
    counts=Counter(r.classification for r in results); blocked=sum(1 for r in results if r.classification=="ACCESS_DENIED"); errors=sum(1 for r in results if r.classification.endswith("ERROR") or r.classification in {"TIMEOUT","TLS_ERROR","CONNECTION_ERROR","PROXY_ERROR"})
    rows="".join(f"<tr><td>{html.escape(r.url)}</td><td>{r.http_status or ''}</td><td>{html.escape(r.final_url)}</td><td>{html.escape(r.classification)}</td><td>{html.escape(r.confidence)}</td><td>{html.escape(r.reason)}</td><td><details><summary>Afficher le HTML ({len(r.page_html):,} caractères)</summary><pre>{html.escape(r.page_html)}</pre></details></td></tr>" for r in results)
    ip=(public_ip_info or {}).get("ip", "Not detected")
    body=f"""<!doctype html><html><head><meta charset='utf-8'><title>SASE validation report</title><style>body{{font-family:Segoe UI,Arial;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.5rem;text-align:left;vertical-align:top}}th{{background:#eee}}pre{{max-width:50rem;max-height:24rem;overflow:auto;white-space:pre-wrap}}</style></head><body><h1>SASE Web Filtering Validation Tool</h1><h2>Test Summary</h2><ul><li>Total URLs: {len(results)}</li><li>Accessible: {counts['ACCESS_ALLOWED']}</li><li>Blocked: {blocked}</li><li>Authentication required: {counts['AUTHENTICATION_REQUIRED']}</li><li>IP restriction detected: {counts['IP_RESTRICTION']}</li><li>Network errors: {errors}</li><li>Unknown: {counts['UNKNOWN']}</li><li>Public IP: {html.escape(ip)}</li></ul><p>ACCESS_DENIED, AUTHENTICATION_REQUIRED, and IP_RESTRICTION are indicators based on observed responses, not definitive proof.</p><p>Le HTML de chaque réponse est inclus dans les exports CSV, Excel et HTML, dans une limite de 1 Mo par page.</p><table><tr><th>URL</th><th>HTTP</th><th>Final URL</th><th>Classification</th><th>Confidence</th><th>Reason</th><th>HTML de la page</th></tr>{rows}</table></body></html>"""
    Path(path).write_text(body,encoding="utf-8")
