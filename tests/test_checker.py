# -*- coding: utf-8 -*-
"""Automated tests for the PKHosting uptime & SSL checker.

All network access is mocked: no test hits the real internet.
Run with:  pytest -q
"""

import csv
import io
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, ".")

from checker import (
    InvalidURLError,
    check_site,
    check_sites,
    get_ssl_expiry,
    normalize_url,
    results_to_csv,
)
import app as webapp


# ---------- normalize_url ----------

def test_normalize_adds_https_when_scheme_missing():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_keeps_explicit_http():
    assert normalize_url("http://example.com") == "http://example.com"


def test_normalize_strips_whitespace_and_case():
    assert normalize_url("  EXAMPLE.com/path ") == "https://example.com/path"


def test_normalize_rejects_empty():
    with pytest.raises(InvalidURLError):
        normalize_url("   ")


def test_normalize_rejects_garbage():
    with pytest.raises(InvalidURLError):
        normalize_url("not a website!!!")


# ---------- check_site (mocked network) ----------

def _mock_response(status=200, url="https://example.com/"):
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    return resp


def test_check_site_success_reports_status_and_timing():
    far_future = datetime.now(timezone.utc) + timedelta(days=300)
    with patch("checker.requests.get", return_value=_mock_response(200)), \
         patch("checker.get_ssl_expiry", return_value=far_future):
        result = check_site("https://example.com")
    assert result["ok"] is True
    assert result["status"] == 200
    assert isinstance(result["response_ms"], int)
    assert result["ssl_expiry"] == far_future.strftime("%Y-%m-%d")
    assert result["ssl_warning"] is False
    assert result["error"] is None


def test_check_site_flags_ssl_expiring_within_30_days():
    soon = datetime.now(timezone.utc) + timedelta(days=9)
    with patch("checker.requests.get", return_value=_mock_response(200)), \
         patch("checker.get_ssl_expiry", return_value=soon):
        result = check_site("https://example.com")
    assert result["ok"] is True
    assert result["ssl_warning"] is True
    assert 8 <= result["ssl_days_left"] <= 9  # day-boundary safe


def test_check_site_http_error_is_not_ok():
    with patch("checker.requests.get", return_value=_mock_response(503)):
        result = check_site("https://example.com")
    assert result["ok"] is False
    assert result["status"] == 503
    assert "503" in result["error"]


def test_check_site_timeout_gives_clear_message():
    with patch("checker.requests.get",
               side_effect=requests.exceptions.ConnectTimeout()):
        result = check_site("https://example.com", timeout=7)
    assert result["ok"] is False
    assert "timed out" in result["error"].lower()
    assert "7" in result["error"]


def test_check_site_connection_error_gives_clear_message():
    with patch("checker.requests.get",
               side_effect=requests.exceptions.ConnectionError("dns failed")):
        result = check_site("https://example.com")
    assert result["ok"] is False
    assert "could not connect" in result["error"].lower()


def test_check_site_plain_http_skips_ssl():
    with patch("checker.requests.get",
               return_value=_mock_response(200, "http://example.com/")), \
         patch("checker.get_ssl_expiry") as ssl_mock:
        result = check_site("http://example.com")
    assert result["ok"] is True
    assert result["ssl_expiry"] is None
    assert result["ssl_warning"] is False
    ssl_mock.assert_not_called()


def test_check_site_ssl_failure_keeps_http_result():
    with patch("checker.requests.get", return_value=_mock_response(200)), \
         patch("checker.get_ssl_expiry",
               side_effect=InvalidURLError("SSL handshake failed.")):
        result = check_site("https://example.com")
    assert result["ok"] is True
    assert result["ssl_expiry"] is None
    assert "SSL" in result["error"]


def test_check_sites_preserves_input_order():
    def fake_get(url, **kwargs):
        return _mock_response(200, url)
    with patch("checker.requests.get", side_effect=fake_get), \
         patch("checker.get_ssl_expiry",
               return_value=datetime.now(timezone.utc) + timedelta(days=100)):
        results = check_sites(["https://b.example", "https://a.example"],
                              max_workers=2)
    assert [r["url"] for r in results] == ["https://b.example", "https://a.example"]


# ---------- results_to_csv ----------

def test_results_to_csv_has_headers_and_rows():
    rows = [{
        "url": "https://example.com", "ok": True, "status": 200,
        "response_ms": 123, "final_url": "https://example.com/",
        "ssl_expiry": "2027-01-01", "ssl_days_left": 400,
        "ssl_warning": False, "error": None,
    }]
    text = results_to_csv(rows)
    parsed = list(csv.reader(io.StringIO(text)))
    assert parsed[0][0] == "url"
    assert parsed[1][0] == "https://example.com"
    assert parsed[1][1] == "True"


# ---------- Flask routes ----------

@pytest.fixture
def client():
    webapp.app.config["TESTING"] = True
    return webapp.app.test_client()


def test_index_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Run checks" in resp.data


def test_check_with_no_urls_shows_error(client):
    resp = client.post("/check", data={"urls": "   "})
    assert resp.status_code == 200
    assert b"at least one website URL" in resp.data


def test_download_returns_csv(client):
    payload = ('[{"url": "https://example.com", "ok": true, "status": 200, '
               '"response_ms": 50, "final_url": "https://example.com/", '
               '"ssl_expiry": null, "ssl_days_left": null, '
               '"ssl_warning": false, "error": null}]')
    resp = client.post("/download", data={"payload": payload})
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "https://example.com" in resp.get_data(as_text=True)
