import argparse
import sys
from urllib.parse import urlparse
from colorama import init, Fore, Style

from modules.crawler import Crawler
from modules.checks import (
    check_security_headers,
    check_cookie_security,
    check_sql_error_indicators,
    check_tech_fingerprint,
    add_severity_scores,
)
from modules.report_generator import generate_report, generate_pdf_report

init(autoreset=True)  # colorama: auto-reset color after each print

# Known Juice Shop REST API endpoints - used as fallback seeds since
# Juice Shop is an Angular SPA and static HTML crawling alone won't
# discover routes that only appear after JS renders the app.
JUICE_SHOP_KNOWN_ENDPOINTS = [
    "/rest/products",
    "/rest/user/login",
    "/rest/user/whoami",
    "/api/Users",
    "/api/Feedbacks",
    "/rest/basket",
    "/rest/products/search",
]

RISK_COLORS = {
    "High": Fore.RED + Style.BRIGHT,
    "Medium": Fore.YELLOW + Style.BRIGHT,
    "Low": Fore.CYAN,
    "Info": Fore.WHITE,
}


def get_target_url():
    parser = argparse.ArgumentParser(
        description="FortifyWebX Web Application Vulnerability Scanner"
    )
    parser.add_argument(
        "-u", "--url",
        help="Target URL to scan (e.g. http://localhost:3000)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay in seconds between requests (default: 0.5, rate limiting)"
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=30,
        help="Maximum pages to crawl (default: 30)"
    )
    args = parser.parse_args()

    target = args.url or input("Enter target URL: ").strip()

    if not validate_url(target):
        print(f"[!] Invalid URL: {target}")
        sys.exit(1)

    return target, args.delay, args.max_pages


def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def get_seed_urls(base_url):
    """Combine the base URL with known fallback endpoints."""
    seeds = [base_url]
    for endpoint in JUICE_SHOP_KNOWN_ENDPOINTS:
        seeds.append(base_url.rstrip("/") + endpoint)
    return seeds


def print_finding(finding):
    color = RISK_COLORS.get(finding["risk"], Fore.WHITE)
    print(f"    {color}[{finding['risk']} | Score: {finding['score']}] {finding['name']}{Style.RESET_ALL} — {finding['location']}")


if __name__ == "__main__":
    target, delay, max_pages = get_target_url()
    print(f"[+] Target validated: {target}")

    print(f"[+] Starting crawl... (delay={delay}s, max_pages={max_pages})")
    seeds = get_seed_urls(target)

    crawler = Crawler(target, max_pages=max_pages, delay=delay)
    crawler.to_visit = seeds
    results = crawler.crawl()

    print(f"\n[+] Crawl complete.")
    print(f"    Pages found: {len(results['pages'])}")
    print(f"    Forms found: {len(results['forms'])}")
    print(f"    Hidden fields found: {len(results['hidden_fields'])}")
    print(f"    Inline scripts found: {len(results['inline_scripts'])}")

    all_findings = []

    print(f"\n[+] Running security header checks...")
    for page in results['pages']:
        all_findings.extend(check_security_headers(page))

    print(f"[+] Running cookie security checks...")
    for page in results['pages']:
        all_findings.extend(check_cookie_security(page))

    print(f"[+] Running SQL error indicator checks...")
    for page in results['pages']:
        all_findings.extend(check_sql_error_indicators(page))

    print(f"[+] Running tech stack fingerprinting...")
    all_findings.extend(check_tech_fingerprint(target))

    all_findings, total_score = add_severity_scores(all_findings)

    print(f"\n{Style.BRIGHT}[+] Total findings: {len(all_findings)}  |  Overall Risk Score: {total_score}{Style.RESET_ALL}")
    for finding in all_findings:
        print_finding(finding)

    md_path = generate_report(target, results, all_findings, total_score)
    pdf_path = generate_pdf_report(target, results, all_findings, total_score)

    print(f"\n[+] Markdown report saved to: {md_path}")
    print(f"[+] PDF report saved to: {pdf_path}")
