# PKHosting - Website Uptime & SSL Expiry Checker

A small Flask web tool for PKHosting.com. Paste website URLs (or upload a CSV file)
and get a colour-coded status report for every site: HTTP status, response time and
SSL certificate expiry, with a warning flag for certificates expiring within 30 days.
A CSV report can be downloaded from the results page.

## What it does

- Accepts URLs pasted as text (one per line) or uploaded as a CSV file.
- Validates every entry; bad entries are listed separately and skipped, not checked.
- For each valid site, in parallel:
  - HTTP status code and response time (follows redirects).
  - SSL certificate expiry date and days remaining (HTTPS sites only). On networks
    that require an HTTP proxy, the check tunnels through the configured proxy.
  - Certificates expiring within 30 days get an amber "SSL expiring" flag.
- Colour-coded results table: green = up, amber = SSL expiring soon, red = down.
- One-click CSV download of the full report.
- Clear, plain-language error messages for unreachable sites and timeouts.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional, defaults work out of the box
python app.py
```

Open http://localhost:5000 in a browser.

Optional settings (environment variables, see `.env.example`):

| Variable      | Default | Meaning                              |
|---------------|---------|--------------------------------------|
| `TIMEOUT`     | 10      | Per-site timeout in seconds (3-60)   |
| `MAX_URLS`    | 50      | Max URLs checked per run             |
| `MAX_WORKERS` | 8       | Parallel check threads               |
| `PORT`        | 5000    | Local server port                    |
| `HTTPS_PROXY` | -       | Proxy URL, only needed behind one    |

## How it was tested

- 17 automated tests in `tests/test_checker.py` (run with `pytest -q`). All network
  access is mocked, so the suite runs offline and in CI.
- Covered: URL normalization and rejection of bad entries, successful checks,
  HTTP error statuses, timeouts, connection failures, plain-HTTP sites skipping
  SSL, SSL handshake failures keeping the HTTP result, the 30-day warning flag,
  result ordering, CSV output, and the Flask routes (form page, empty input,
  CSV download).
- Manual end-to-end run locally: pasted real URLs plus a bad entry, confirmed the
  colour-coded table, the skipped-entry list and the downloaded CSV.

## Limitations

- The SSL check reads the certificate presented on port 443; it does not validate
  the full chain beyond what the OS trust store says during the handshake.
- Very slow sites are cut off by the timeout setting; raise it for such sites.
- The free serverless hosting used for the demo may cold-start on first request.
- Only the first `MAX_URLS` entries per run are checked; split larger lists.
