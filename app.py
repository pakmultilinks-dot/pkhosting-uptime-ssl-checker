# -*- coding: utf-8 -*-
"""
PKHosting Website Uptime & SSL Expiry Checker.

Paste website URLs (or upload a CSV) and get a colour-coded status report:
HTTP status, response time and SSL certificate expiry for every site.

Run locally:
    pip install -r requirements.txt
    python app.py
"""

import csv
import io
import json
import os

from dotenv import load_dotenv
from flask import Flask, Response, render_template, request

from checker import (
    DEFAULT_TIMEOUT,
    InvalidURLError,
    check_sites,
    normalize_url,
    results_to_csv,
)

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB upload cap

MAX_URLS = int(os.environ.get("MAX_URLS", "50"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "8"))


def collect_raw_urls():
    """Gather raw URL entries from the textarea and/or an uploaded CSV."""
    raw = []
    pasted = request.form.get("urls", "")
    for line in pasted.replace(",", "\n").splitlines():
        line = line.strip().strip('"').strip("'")
        if line:
            raw.append(line)
    upload = request.files.get("csv_file")
    if upload and upload.filename:
        name = upload.filename.lower()
        if not name.endswith(".csv"):
            raise InvalidURLError("Uploaded file must be a .csv file.")
        try:
            text = upload.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            raise InvalidURLError("Could not read the CSV file as text.")
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            for cell in row:
                cell = (cell or "").strip().strip('"').strip("'")
                if cell and not cell.lower().startswith(("http", "www", "url", "website")):
                    # Skip header-ish cells only when they look like headers.
                    if cell.lower() in ("url", "urls", "website", "websites", "site", "sites"):
                        continue
                    raw.append(cell)
    # De-duplicate while keeping order.
    seen = set()
    unique = []
    for entry in raw:
        key = entry.lower()
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", results=None, invalid=[], error=None)


@app.route("/check", methods=["POST"])
def check():
    try:
        timeout = int(request.form.get("timeout", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = max(3, min(timeout, 60))

    try:
        raw_urls = collect_raw_urls()
    except InvalidURLError as exc:
        return render_template("index.html", results=None, invalid=[], error=str(exc))

    if not raw_urls:
        return render_template(
            "index.html", results=None, invalid=[],
            error="Enter at least one website URL, or upload a CSV file.",
        )
    if len(raw_urls) > MAX_URLS:
        return render_template(
            "index.html", results=None, invalid=[],
            error="Too many URLs (max %d per run). Split the list and try again." % MAX_URLS,
        )

    valid, invalid = [], []
    for entry in raw_urls:
        try:
            valid.append(normalize_url(entry))
        except InvalidURLError as exc:
            invalid.append({"entry": entry, "error": str(exc)})

    results = check_sites(valid, timeout=timeout, max_workers=MAX_WORKERS)
    payload = json.dumps(results)
    return render_template("index.html", results=results, invalid=invalid,
                           error=None, payload=payload)


@app.route("/download", methods=["POST"])
def download():
    try:
        results = json.loads(request.form.get("payload", "[]"))
    except (TypeError, ValueError):
        results = []
    csv_text = results_to_csv(results)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=uptime-report.csv"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
