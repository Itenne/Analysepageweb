# SASE Web Filtering Validation Tool

Local, user-space diagnostic application for validating normal HTTP/HTTPS access through the workstation's existing network and proxy/SASE path. It does **not** modify routing, DNS, system proxy settings, TLS verification, or use bypass mechanisms.

## Architecture

- `app/security.py`: validates absolute HTTP(S) URLs and rejects local/private, loopback, link-local, and reserved destinations.
- `app/parsers.py`, `dns_checker.py`, `http_client.py`: input parsing; DNS and one normal GET request (plus normal redirects) using `requests` and OS proxy settings by default.
- `classifier.py` and `config/signatures.json`: configurable, multi-signal block/IP-restriction detection.
- `public_ip.py`: compares two public IP observation services.
- `ui.py` and `exporters.py`: Tkinter desktop interface and CSV/HTML reporting.

Results are structured dataclasses and CSV fields, so a future before/after report comparer can use stable URL, final URL, status, and classification fields.

## Install and run

Requires Python 3.10+ and Tkinter (normally included with Windows Python).

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m app.main
```

No administrator privileges are required. The tool uses Requests' standard environment proxy discovery (`Session.trust_env=True`); it neither edits proxy configuration nor establishes a direct/bypass path.

## Input

Load `.txt` with one URL per line, or `.csv` with a `url` column. CSV comma and semicolon delimiters are accepted. Extra columns such as `name` and `expected` are preserved during parsing for future use. See `sample/urls.csv`.

## Operation

1. Select **Load URLs** or **Add URL**.
2. Select **Detect Public IP**. Two configurable endpoints are queried. Matching observations yield HIGH confidence; differing values yield LOW.
3. Select **Test All**. Tests run in a pool of five, so an individual timeout does not stall the UI or other URLs.
4. Select a result for DNS, status, indicator, and error details. Export CSV or HTML.

The user agent is `SASE-Web-Validation-Tool/0.1.0`; TLS certificates are always verified. The response analysis is bounded to 64 KiB and only selected headers, title, and detected indicators are retained in results/logging.

## Detection and limitations

A 403 alone remains `HTTP_403`. `ACCESS_DENIED` requires an access-denial HTTP status and corroborating configurable blocking signals (two signatures, or a signature plus proxy/SASE header). `IP_RESTRICTION` is prioritized when configured IP-specific text is observed. Add languages or vendor wording in `config/signatures.json` without code changes.

> `ACCESS_DENIED` and `IP_RESTRICTION` are indications based on observed response data and are not definitive proof of the cause of a block.

HTTP status, redirects, DNS, and error classes are diagnostic observations only. Some proxies hide remote IPs; public-IP providers may be unavailable or intentionally blocked. This tool does not authenticate, collect credentials/cookies/tokens, scan ports, fuzz, or retrieve full page content.

## Windows executable

On Windows, after installing dependencies:

```powershell
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --add-data "config;config" --name SASEWebValidator app\main.py
```

Run `dist\SASEWebValidator.exe` as the standard user. Keep `config/signatures.json` adjacent to the packaged resource as appropriate for your PyInstaller deployment; test signature loading after packaging.

## Tests

```bash
python -m unittest discover -s tests -v
```
