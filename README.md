# SQL Injection Scanner

A Python-based web security testing script that crawls a target site and checks forms + API-like endpoints for possible SQL injection behavior.

## What this script does

The scanner starts from one URL and performs a breadth-first crawl (up to depth 3). During crawling, it:

- collects links from HTML pages (same domain only)
- extracts likely auth/API endpoints from inline and external JavaScript
- detects and parses HTML forms
- tests discovered forms and API endpoints with multiple SQLi techniques

The script is intended for **authorized security testing** and learning purposes.

## How it works (step by step)

### 1) Session setup

The script creates a shared `requests.Session()` and sets a browser-like User-Agent.

Why this matters:
- keeps connection behavior consistent
- can improve compatibility with sites that filter non-browser traffic

### 2) Crawl + endpoint discovery

Starting from your input URL, `test_sql_injection()`:

- keeps a `visited` set to avoid rescanning the same URL
- uses a queue (`collections.deque`) for BFS crawling
- limits recursion with `max_depth = 3`
- filters out non-useful links (`mailto:`, anchors, binary files, off-domain links)

It also tries to find hidden API routes by scanning JavaScript:

- `extract_js_endpoints()` finds paths related to login/auth flows
- `extract_api_endpoints()` uses regex patterns like `/api/...`, `/auth/...`, `/rest/...`

### 3) Form extraction

For HTML responses only, `get_forms()` parses the page with BeautifulSoup and returns all forms.

For each form, `get_form_details()` collects:
- form action
- HTTP method (`GET` or `POST`)
- all input/textarea fields (`name`, `type`, default value)

### 4) SQL injection checks

The scanner uses three detection styles:

#### A. Error-based SQLi

For each form field, it injects quote payloads (`'` and `"`) and submits requests.

Then `detect_sql_error()` searches response text for common DB error signatures, for example:
- `sql syntax`
- `warning: mysql`
- `sqlite error`
- `unclosed quotation mark`

If matched, the form is flagged as potentially vulnerable.

#### B. Boolean-based SQLi (JSON/API)

For API-like endpoints, `test_boolean_sqli()` posts:
- normal credentials
- a true condition payload (`' OR 1=1--`)
- a false condition payload (`' OR 1=2--`)

It compares:
- response size/content differences
- JSON key structure changes
- keyword differences (`welcome`, `success`, `invalid`, `error`)

Meaningful true/false response differences may indicate SQLi behavior.

#### C. Time-based SQLi

The script tests delay payloads such as:
- MySQL/MariaDB style: `SLEEP(5)`
- PostgreSQL style: `pg_sleep(5)`

It measures baseline response time, then compares with payload response time.

If `avg(payload) - avg(baseline) >= 4.0s`, it reports possible time-based SQLi.

This is used for:
- forms (`test_time_sqli_form()`)
- JSON APIs (`test_time_sqli_json()`)

## Technologies used

### Python Standard Library

- `collections.deque` — BFS crawl queue
- `urllib.parse` — URL normalization and joining
- `re` — endpoint and content pattern matching
- `json` — JSON structure comparison
- `time`, `statistics` — timing-based detection

### Third-party libraries

- `requests` — HTTP client (GET/POST + sessions)
- `beautifulsoup4` (`bs4`) — HTML parsing and form extraction

## Project files

- `Sql-injection-scanner.py` — main scanner script
- `README.md` — project documentation
- `requirements.txt` — Python dependency list

## Installation

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the scanner:

```bash
python Sql-injection-scanner.py
```

Then enter the target URL when prompted.

## Notes and limitations

- This is a heuristic scanner, so false positives/false negatives are possible.
- Some endpoints may block automated traffic (WAF/rate limits/CAPTCHA).
- Timing results depend on network stability and server load.
- Crawling is intentionally conservative (`max_depth = 3`).

## Legal and ethical use

Use this tool **only** on systems you own or have explicit permission to test.
Unauthorized scanning may violate laws and policies.
