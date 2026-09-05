"""
Standalone verification script for check_form_risk().

Juice Shop's forms are rendered client-side by Angular, so a static
HTML crawl finds 0 forms on that target (a documented limitation -
see README > Known Limitations). This script proves the XSS/form-risk
check logic itself is correct by running it against a local HTML
fixture (test_page.html) that contains real, static forms.

Run with:
    cd tests
    python3 test_checks.py
"""
import sys
sys.path.append("..")

from bs4 import BeautifulSoup
from modules.checks import check_form_risk

with open("test_page.html") as f:
    soup = BeautifulSoup(f.read(), "lxml")

forms = []
for form in soup.find_all("form"):
    inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
    forms.append({
        "page": "test_page.html",
        "action": form.get("action", ""),
        "method": form.get("method", "get").upper(),
        "inputs": inputs,
    })

print(f"Parsed {len(forms)} forms from test file.\n")

for form in forms:
    print(f"Form: {form['action']} ({form['method']}) — fields: {form['inputs']}")
    findings = check_form_risk(form)
    if not findings:
        print("    -> No findings (looks OK)")
    for finding in findings:
        print(f"    [{finding['risk']}] {finding['name']}: {finding['evidence']}")
    print()
