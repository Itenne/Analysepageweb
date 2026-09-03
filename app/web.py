"""Local-only Flask UI. It intentionally never listens on the LAN."""
from __future__ import annotations
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename
from .exporters import export_csv, export_html
from .http_client import WebTester
from .parsers import parse_csv, parse_txt
from .public_ip import detect_public_ip
from .signatures import load_signatures
from .targets import unique_urls_by_fqdn

MAX_UPLOAD_BYTES = 1_000_000


class TestRun:
    def __init__(self, tester: WebTester):
        self.tester = tester
        self.lock = threading.Lock()
        self.results = []
        self.urls = []
        self.public_ip = {}
        self.state = "idle"
        self.completed = 0
        self.cancel = threading.Event()
        self.output_dir = Path.home() / ".sase-web-validator" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def snapshot(self):
        with self.lock:
            return {"state": self.state, "total": len(self.urls), "completed": self.completed,
                    "public_ip": self.public_ip, "results": [item.to_dict() for item in self.results]}

    def start(self, urls: list[str], workers: int = 5):
        with self.lock:
            if self.state == "running":
                raise ValueError("A test run is already in progress")
            self.urls = unique_urls_by_fqdn(urls)
            self.tester.clear_dns_cache()
            self.results, self.completed = [], 0
            self.state = "running"
            self.cancel.clear()
        threading.Thread(target=self._run, args=(max(1, min(workers, 20)),), daemon=True).start()

    def _run(self, workers: int):
        logging.info("Starting web test run urls=%s workers=%s", len(self.urls), workers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.tester.test, url, self.public_ip.get("ip", "")): url for url in self.urls}
            for future in as_completed(futures):
                if self.cancel.is_set():
                    for pending in futures:
                        pending.cancel()
                    break
                try:
                    result = future.result()
                except Exception as exc:  # Defensive boundary: worker errors must not crash the local UI.
                    logging.exception("Unexpected test worker error")
                    continue
                with self.lock:
                    self.results.append(result)
                    self.completed += 1
        with self.lock:
            self.state = "cancelled" if self.cancel.is_set() else "complete"
        logging.info("Finished web test run state=%s", self.state)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES, SECRET_KEY=uuid.uuid4().hex)
    run = TestRun(WebTester(load_signatures()))
    app.extensions["test_run"] = run

    @app.get("/")
    def index():
        return render_template("index.html", version="0.2.0")

    @app.post("/api/urls")
    def add_urls():
        payload = request.get_json(silent=True) or {}
        text = str(payload.get("text", ""))
        fmt = payload.get("format", "txt")
        try:
            rows = parse_csv(text) if fmt == "csv" else parse_txt(text)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        with run.lock:
            if run.state == "running":
                return jsonify(error="Cannot change URLs while testing"), 409
            run.urls.extend(row["url"] for row in rows)
        return jsonify(count=len(rows), urls=run.urls)

    @app.post("/api/upload")
    def upload_urls():
        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify(error="A .txt or .csv file is required"), 400
        name = secure_filename(file.filename)
        suffix = Path(name).suffix.lower()
        if suffix not in {".txt", ".csv"}:
            return jsonify(error="Only .txt and .csv files are supported"), 400
        text = file.read(MAX_UPLOAD_BYTES + 1).decode("utf-8-sig", errors="strict")
        if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
            return jsonify(error="File exceeds 1 MB limit"), 413
        return add_parsed(text, suffix)

    def add_parsed(text, suffix):
        try:
            rows = parse_csv(text) if suffix == ".csv" else parse_txt(text)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        with run.lock:
            if run.state == "running":
                return jsonify(error="Cannot change URLs while testing"), 409
            run.urls.extend(row["url"] for row in rows)
        return jsonify(count=len(rows), urls=run.urls)

    @app.post("/api/public-ip")
    def public_ip():
        def task():
            observed = detect_public_ip(use_system_proxy=run.tester.session.trust_env)
            with run.lock:
                run.public_ip = observed
        threading.Thread(target=task, daemon=True).start()
        return jsonify(status="started"), 202

    @app.post("/api/test")
    def start_test():
        payload = request.get_json(silent=True) or {}
        try:
            run.start(run.urls, int(payload.get("workers", 5)))
        except ValueError as exc:
            return jsonify(error=str(exc)), 409
        return jsonify(status="started"), 202

    @app.post("/api/stop")
    def stop_test():
        run.cancel.set()
        logging.info("User requested test stop")
        return jsonify(status="stopping")

    @app.post("/api/clear")
    def clear():
        with run.lock:
            if run.state == "running":
                return jsonify(error="Stop the active test first"), 409
            run.urls, run.results, run.completed, run.state = [], [], 0, "idle"
        return jsonify(status="cleared")

    @app.get("/api/status")
    def status():
        return jsonify(run.snapshot())

    @app.get("/api/export/<format>")
    def export(format):
        if format not in {"csv", "html"}:
            return jsonify(error="Unsupported format"), 404
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = run.output_dir / f"sase-validation-{timestamp}.{format}"
        with run.lock:
            if format == "csv": export_csv(run.results, output)
            else: export_html(run.results, output, run.public_ip)
        return send_file(output, as_attachment=True, download_name=output.name)

    return app
