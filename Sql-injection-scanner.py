import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")


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

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def vulnerable_to_sql_injection(response):
    errors = [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql syntax error",
    ]
    return any(error in response.text.lower() for error in errors)


def test_sql_injection(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = get_form_details(form)
        vulnerable = False

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["name"] is None:
                    continue
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + i
                else:
                    data[input_tag["name"]] = f"test{i}"

            target_url = urljoin(url, details["action"])

            if details["method"] == "post":
                res = s.post(target_url, data=data)
            else:
                res = s.get(target_url, params=data)

            if vulnerable_to_sql_injection(res):
                print(f"[!!!] SQL Injection vulnerability detected in form at {target_url}")
                vulnerable = True
                break

        if not vulnerable:
            print(f" No SQL Injection vulnerability detected in form at {url}")


if __name__ == "__main__":
    url = input("Enter the URL to test for SQL Injection: ").strip()
    test_sql_injection(url)
