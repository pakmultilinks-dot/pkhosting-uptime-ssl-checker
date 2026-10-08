# -*- coding: utf-8 -*-
"""
PKHosting Website Uptime & SSL Expiry Checker - core logic.

check_site(url) returns a dict with:
    url            normalized URL that was checked
    ok             True when the site answered with HTTP status < 400
    status         HTTP status code (None when the request never completed)
    response_ms    response time in milliseconds (None on failure)
    final_url      URL after following redirects
    ssl_expiry     SSL certificate expiry as "YYYY-MM-DD" (None for plain http
                   or when the certificate could not be read)
    ssl_days_left  days until expiry (None when unknown)
    ssl_warning    True when the certificate expires within 30 days
    error          human-readable error message (None on success)
"""

import csv
import io
import os
import socket
import ssl
import time
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

import requests

DEFAULT_TIMEOUT = 10
SSL_WARNING_DAYS = 30
USER_AGENT = "PKHosting-Uptime-Checker/1.0"


class InvalidURLError(ValueError):
    """Raised when a pasted/uploaded entry is not a usable website URL."""


def normalize_url(raw):
    """Clean a raw entry and return a full URL, or raise InvalidURLError."""
    text = (raw or "").strip().strip("<>").strip()
    if not text:
        raise InvalidURLError("Empty entry.")
    # Drop a trailing slash-only path but keep real paths.
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlparse(text)
    except Exception:
        raise InvalidURLError("Not a valid URL: %r." % raw)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        raise InvalidURLError("Not a valid website address: %r." % raw)
    if "." not in host and host != "localhost":
        raise InvalidURLError("Not a valid website address: %r." % raw)
    if any(ch.isspace() for ch in host):
        raise InvalidURLError("Not a valid website address: %r." % raw)
    return "%s://%s%s" % (parts.scheme, host, parts.path or "")


def _direct_socket(host, port, timeout):
    return socket.create_connection((host, port), timeout=timeout)


def _proxy_socket(proxy_url, host, port, timeout):
    """Open a TCP tunnel to host:port through an HTTP proxy (CONNECT)."""
    proxy = urlparse(proxy_url)
    sock = socket.create_connection(
        (proxy.hostname, proxy.port or 8080), timeout=timeout)
    try:
        request_lines = [
            "CONNECT %s:%d HTTP/1.1" % (host, port),
            "Host: %s:%d" % (host, port),
        ]
        if proxy.username:
            user = unquote(proxy.username)
            password = unquote(proxy.password or "")
            token = b64encode(("%s:%s" % (user, password)).encode()).decode()
            request_lines.append("Proxy-Authorization: Basic " + token)
        request_lines += ["", ""]
        sock.sendall("\r\n".join(request_lines).encode("latin1"))
        stream = sock.makefile("rb")
        status_line = stream.readline().decode("latin1", "replace")
        if " 200 " not in status_line:
            raise OSError("proxy refused CONNECT: %s" % status_line.strip())
        while stream.readline().strip():  # consume response headers
            pass
        return sock
    except Exception:
        sock.close()
        raise


def _expiry_from_socket(sock, host):
    """Run the TLS handshake on an open socket and parse the expiry date."""
    context = ssl.create_default_context()
    try:
        tls = context.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise
    try:
        cert = tls.getpeercert()
    finally:
        tls.close()
    not_after = (cert or {}).get("notAfter")
    if not not_after:
        raise InvalidURLError("No expiry date found in %s certificate." % host)
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        raise InvalidURLError("Unparseable expiry date in %s certificate." % host)
    return expiry.replace(tzinfo=timezone.utc)


def get_ssl_expiry(host, timeout=DEFAULT_TIMEOUT):
    """Return the peer certificate expiry as an aware datetime.

    Tries a direct TLS connection first, then a proxy CONNECT tunnel when
    an HTTPS proxy is configured (corporate/sandbox networks). Raises
    InvalidURLError with a plain message when anything goes wrong.
    """
    attempts = []  # (label, socket_factory)

    def direct():
        return _direct_socket(host, 443, timeout)

    attempts.append(("direct", direct))
    proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy_url:
        def via_proxy(url=proxy_url):
            return _proxy_socket(url, host, 443, timeout)

        attempts.append(("proxy", via_proxy))

    last_error = None
    for label, make_socket in attempts:
        try:
            sock = make_socket()
        except socket.timeout as exc:
            last_error = "Timed out reaching %s (%s)." % (host, label)
            continue
        except OSError as exc:
            last_error = "Could not connect to %s (%s): %s." % (
                host, label, exc.strerror or exc)
            continue
        try:
            return _expiry_from_socket(sock, host)
        except InvalidURLError as exc:
            # Cert had no parseable date; no point retrying another route.
            raise
        except (ssl.SSLError, OSError) as exc:
            last_error = "SSL handshake with %s (%s) failed: %s." % (host, label, exc)
            continue
    raise InvalidURLError(last_error or "Could not read SSL certificate from %s." % host)


def check_site(url, timeout=DEFAULT_TIMEOUT):
    """Check one normalized URL and return the result dict."""
    result = {
        "url": url,
        "ok": False,
        "status": None,
        "response_ms": None,
        "final_url": None,
        "ssl_expiry": None,
        "ssl_days_left": None,
        "ssl_warning": False,
        "error": None,
    }
    host = urlparse(url).hostname or ""
    started = time.monotonic()
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
    except requests.exceptions.Timeout:
        result["error"] = "Timed out after %ss waiting for %s." % (timeout, host)
        return result
    except requests.exceptions.ConnectionError:
        result["error"] = (
            "Could not connect to %s. The site may be down, the domain may not "
            "exist, or the network blocked the connection." % host
        )
        return result
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects when requesting %s." % host
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = "Request to %s failed: %s." % (host, exc)
        return result

    result["status"] = resp.status_code
    result["response_ms"] = elapsed_ms
    result["final_url"] = resp.url
    result["ok"] = resp.status_code < 400
    if not result["ok"]:
        result["error"] = "Site answered with HTTP %s." % resp.status_code

    if urlparse(url).scheme == "https":
        try:
            expiry = get_ssl_expiry(host, timeout=timeout)
        except InvalidURLError as exc:
            result["error"] = (result["error"] + " " if result["error"] else "") + str(exc)
        else:
            days_left = (expiry - datetime.now(timezone.utc)).days
            result["ssl_expiry"] = expiry.strftime("%Y-%m-%d")
            result["ssl_days_left"] = days_left
            result["ssl_warning"] = days_left <= SSL_WARNING_DAYS
    return result


def check_sites(urls, timeout=DEFAULT_TIMEOUT, max_workers=8):
    """Check many normalized URLs concurrently, preserving input order."""
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(lambda u: check_site(u, timeout), urls))


def results_to_csv(results):
    """Render check results as CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "url", "ok", "http_status", "response_ms", "final_url",
        "ssl_expiry", "ssl_days_left", "ssl_warning", "error",
    ])
    for r in results:
        writer.writerow([
            r["url"], r["ok"], r["status"], r["response_ms"], r["final_url"],
            r["ssl_expiry"], r["ssl_days_left"], r["ssl_warning"], r["error"],
        ])
    return buf.getvalue()
