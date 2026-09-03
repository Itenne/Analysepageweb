from __future__ import annotations
import logging
from pathlib import Path
import tkinter as tk
from .http_client import WebTester
from .signatures import load_signatures
from .ui import ValidatorUI
VERSION="0.1.0"
def configure_logging():
    log_dir=Path.home()/".sase-web-validator"; log_dir.mkdir(exist_ok=True)
    logging.basicConfig(filename=log_dir/"validator.log",level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
def main():
    configure_logging(); logging.info("Started SASE Web Filtering Validation Tool version %s",VERSION)
    root=tk.Tk(); ValidatorUI(root,WebTester(load_signatures())); root.mainloop()
if __name__ == "__main__": main()
