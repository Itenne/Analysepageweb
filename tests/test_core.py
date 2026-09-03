import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from app.classifier import classify
from app.models import TestResult
from app.parsers import load_urls
from app.exporters import export_csv, export_excel, export_html
from app.dns_checker import resolve
from app.security import UrlValidationError, validate_url
from app.targets import unique_urls_by_fqdn
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
 def test_authentication_page_classification(self):
  r=TestResult("https://example.com",http_status=200,page_title="Sign in",headers={"X-Analysis-Snippet":"Please authenticate"})
  self.assertEqual(classify(r,{"blocking":[],"ip_restriction":[],"authentication":["sign in","authenticate"],"proxy_headers":[]}).classification,"AUTHENTICATION_REQUIRED")
  r=TestResult("https://example.com",http_status=401)
  self.assertEqual(classify(r,{"blocking":[],"ip_restriction":[],"authentication":[],"proxy_headers":[]}).classification,"AUTHENTICATION_REQUIRED")
 def test_plain_403_not_blocked(self):
  r=TestResult("https://example.com",http_status=403); self.assertEqual(classify(r,{"blocking":["blocked"],"ip_restriction":[],"proxy_headers":[]}).classification,"HTTP_403")
 def test_dns_error(self):
  with patch("app.dns_checker.socket.getaddrinfo",side_effect=__import__('socket').gaierror()): self.assertEqual(resolve("invalid.example").status,"DNS_ERROR")
 def test_urls_with_same_fqdn_are_only_tested_once(self):
  urls=["https://Example.com/a", "http://example.com/b", "https://other.example/"]
  self.assertEqual(unique_urls_by_fqdn(urls), ["https://Example.com/a", "https://other.example/"])
 def test_exports(self):
  r=TestResult("https://example.com",classification="ACCESS_ALLOWED")
  with tempfile.TemporaryDirectory() as d:
   csv_path=Path(d)/"x.csv"; excel_path=Path(d)/"x.xlsx"; html_path=Path(d)/"x.html"; export_csv([r],csv_path); export_excel([r],excel_path,{"ip":"203.0.113.1"}); export_html([r],html_path,{"ip":"203.0.113.1"})
   self.assertIn("classification",csv_path.read_text()); self.assertIn("Test Summary",html_path.read_text())
   from zipfile import ZipFile
   with ZipFile(excel_path) as workbook:
    self.assertIn("ACCESS_ALLOWED",workbook.read("xl/worksheets/sheet2.xml").decode()); self.assertIn("203.0.113.1",workbook.read("xl/worksheets/sheet1.xml").decode())

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
 @unittest.skipUnless(__import__("importlib").util.find_spec("requests"), "requests dependency is not installed")
 def test_fqdn_dns_lookup_is_cached(self):
  from app.http_client import WebTester
  from app.models import DnsResult
  tester=WebTester({"blocking":[],"ip_restriction":[],"proxy_headers":[]})
  with patch("app.http_client.resolve",return_value=DnsResult("OK",["93.184.216.34"])) as lookup, patch.object(tester.session,"get",side_effect=__import__('requests').exceptions.ConnectTimeout()):
   tester.test("https://example.com/one")
   tester.test("https://example.com/two")
  lookup.assert_called_once_with("example.com")
