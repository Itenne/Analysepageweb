"""Run the portable local web interface on loopback only."""
from __future__ import annotations
import logging
import webbrowser
from pathlib import Path
from .web import create_app
VERSION = "0.2.0"

def configure_logging():
    log_dir = Path.home() / ".sase-web-validator"
    log_dir.mkdir(exist_ok=True)
    logging.basicConfig(filename=log_dir / "validator.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

def main():
    configure_logging()
    logging.info("Started SASE Web Filtering Validation Tool version %s", VERSION)
    url = "http://127.0.0.1:8080"
    webbrowser.open(url)
    create_app().run(host="127.0.0.1", port=8080, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
