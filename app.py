from flask import Flask, render_template, request, send_from_directory
from urllib.parse import urlparse
import os

from modules.crawler import Crawler
from modules.checks import (
    check_security_headers,
    check_cookie_security,
    check_sql_error_indicators,
    check_tech_fingerprint,
    add_severity_scores,
)
from modules.report_generator import generate_report, generate_pdf_report

app = Flask(__name__)

JUICE_SHOP_KNOWN_ENDPOINTS = [
    "/rest/products", "/rest/user/login", "/rest/user/whoami",
    "/api/Users", "/api/Feedbacks", "/rest/basket", "/rest/products/search",
]


def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def get_seed_urls(base_url):
    seeds = [base_url]
    for endpoint in JUICE_SHOP_KNOWN_ENDPOINTS:
        seeds.append(base_url.rstrip("/") + endpoint)
    return seeds


def run_scan(target, delay, max_pages):
    """Runs the full scan pipeline and returns (results, findings, total_score, md_path, pdf_path)."""
    seeds = get_seed_urls(target)
    crawler = Crawler(target, max_pages=max_pages, delay=delay)
    crawler.to_visit = seeds
    results = crawler.crawl()

    all_findings = []
    for page in results['pages']:
        all_findings.extend(check_security_headers(page))
    for page in results['pages']:
        all_findings.extend(check_cookie_security(page))
    for page in results['pages']:
        all_findings.extend(check_sql_error_indicators(page))
    all_findings.extend(check_tech_fingerprint(target))

    all_findings, total_score = add_severity_scores(all_findings)

    md_path = generate_report(target, results, all_findings, total_score)
    pdf_path = generate_pdf_report(target, results, all_findings, total_score)

    return results, all_findings, total_score, md_path, pdf_path


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    delay = float(request.form.get("delay", 0.5))
    max_pages = int(request.form.get("max_pages", 30))

    if not validate_url(target):
        return render_template("index.html", error=f"Invalid URL: {target}")

    results, findings, total_score, md_path, pdf_path = run_scan(target, delay, max_pages)

    risk_order = ["High", "Medium", "Low", "Info"]
    grouped = {level: [f for f in findings if f["risk"] == level] for level in risk_order}
    counts = {level: len(grouped[level]) for level in risk_order}

    return render_template(
        "results.html",
        target=target,
        results=results,
        findings=findings,
        grouped=grouped,
        counts=counts,
        total_score=total_score,
        md_filename=os.path.basename(md_path),
        pdf_filename=os.path.basename(pdf_path),
    )


@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory("reports", filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
