import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from app.classifier import classify
from app.models import TestResult
from app.parsers import load_urls
from app.exporters import export_csv, export_html
from app.dns_checker import resolve
from app.security import UrlValidationError, validate_url
class CoreTests(unittest.TestCase):
 def test_txt_and_csv_parsing(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"urls.txt"; p.write_text("https://example.com\n")
   c=Path(d)/"urls.csv"; c.write_text("url;name\nhttps://example.com;Example\n")
   self.assertEqual(load_urls(p)[0]["url"],"https://example.com"); self.assertEqual(load_urls(c)[0]["name"],"Example")
 def test_rejects_local_url(self):
  with self.assertRaises(UrlValidationError): validate_url("http://localhost")
 def test_block_and_ip_classification(self):
  sig={"blocking":["blocked by policy","access denied"],"ip_restriction":["ip address not allowed"],"proxy_headers":["via"]}
  r=TestResult("https://example.com",http_status=403,headers={"Via":"proxy","X-Analysis-Snippet":"blocked by policy access denied"}); self.assertEqual(classify(r,sig).classification,"ACCESS_DENIED")
  r=TestResult("https://example.com",http_status=403,headers={"X-Analysis-Snippet":"IP address not allowed"}); self.assertEqual(classify(r,sig).classification,"IP_RESTRICTION")
 def test_plain_403_not_blocked(self):
  r=TestResult("https://example.com",http_status=403); self.assertEqual(classify(r,{"blocking":["blocked"],"ip_restriction":[],"proxy_headers":[]}).classification,"HTTP_403")
 def test_dns_error(self):
  with patch("app.dns_checker.socket.getaddrinfo",side_effect=__import__('socket').gaierror()): self.assertEqual(resolve("invalid.example").status,"DNS_ERROR")
 def test_exports(self):
  r=TestResult("https://example.com",classification="ACCESS_ALLOWED")
  with tempfile.TemporaryDirectory() as d:
   csv_path=Path(d)/"x.csv"; html_path=Path(d)/"x.html"; export_csv([r],csv_path); export_html([r],html_path,{"ip":"203.0.113.1"})
   self.assertIn("classification",csv_path.read_text()); self.assertIn("Test Summary",html_path.read_text())

class HttpClientTests(unittest.TestCase):
 @unittest.skipUnless(__import__("importlib").util.find_spec("requests"), "requests dependency is not installed")
 def test_timeout_and_tls_error_are_distinct(self):
  from requests import exceptions
  from app.http_client import WebTester
  tester=WebTester({"blocking":[],"ip_restriction":[],"proxy_headers":[]})
  with patch("app.http_client.resolve",return_value=__import__('app.models',fromlist=['DnsResult']).DnsResult("OK",["93.184.216.34"])), patch.object(tester.session,"get",side_effect=exceptions.ConnectTimeout("slow")):
   self.assertEqual(tester.test("https://example.com").classification,"TIMEOUT")
  with patch("app.http_client.resolve",return_value=__import__('app.models',fromlist=['DnsResult']).DnsResult("OK",["93.184.216.34"])), patch.object(tester.session,"get",side_effect=exceptions.SSLError("bad cert")):
   self.assertEqual(tester.test("https://example.com").classification,"TLS_ERROR")
