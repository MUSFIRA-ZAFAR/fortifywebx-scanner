import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time


class Crawler:
    """
    Non-intrusive web crawler. Performs a breadth-first crawl of a
    target, discovering pages, forms, hidden fields, and inline
    scripts using only standard GET requests (no exploitation).
    """

    def __init__(self, base_url, max_pages=50, delay=0.5):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.delay = delay  # polite delay between requests (rate limiting)

        self.visited = set()
        self.to_visit = [base_url]

        self.pages = []
        self.forms = []
        self.hidden_fields = []
        self.inline_scripts = []

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.base_domain

    def crawl(self):
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop(0)

            if url in self.visited:
                continue

            print(f"[*] Crawling: {url}")
            html, content_type, status_code = self.fetch(url)
            self.visited.add(url)

            if html is None:
                continue

            self.pages.append(url)

            # Only parse as HTML if the response actually is HTML and
            # was not an error response. Error pages (4xx/5xx) and
            # JSON/API responses (e.g. Juice Shop's /rest/ and /api/
            # endpoints) get recorded as discovered endpoints but are
            # NOT parsed for links/forms — running BeautifulSoup's HTML
            # parser on JSON or stack-trace pages produces garbage
            # matches (e.g. URLs embedded inside JSON text get misread
            # as page links).
            try:
                if status_code and status_code >= 400:
                    print(f"    [i] HTTP {status_code} — recorded as endpoint, not parsed for links")
                elif content_type and "text/html" in content_type:
                    soup = BeautifulSoup(html, "lxml")
                    self.extract_links(url, soup)
                    self.extract_forms(url, soup)
                    self.extract_hidden_fields(url, soup)
                    self.extract_inline_scripts(url, soup)
                else:
                    print(f"    [i] Non-HTML content ({content_type}) — recorded as endpoint, not parsed for links")
            except Exception as e:
                # A single page with unexpected/malformed markup should
                # never crash the entire scan — record it and move on.
                print(f"[!] Parsing error on {url}: {e}")

            time.sleep(self.delay)  # avoid hammering the target

        return {
            "pages": self.pages,
            "forms": self.forms,
            "hidden_fields": self.hidden_fields,
            "inline_scripts": self.inline_scripts,
        }

    def fetch(self, url):
        try:
            response = requests.get(url, timeout=5)
            content_type = response.headers.get("Content-Type", "")
            return response.text, content_type, response.status_code
        except requests.RequestException as e:
            print(f"[!] Failed to fetch {url}: {e}")
            return None, None, None

    def extract_links(self, current_url, soup):
        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(current_url, a_tag["href"])
            full_url = full_url.split("#")[0]  # strip fragments

            if self.is_same_domain(full_url) and full_url not in self.visited:
                if full_url not in self.to_visit:
                    self.to_visit.append(full_url)

    def extract_forms(self, current_url, soup):
        for form in soup.find_all("form"):
            action = urljoin(current_url, form.get("action", ""))
            method = form.get("method", "get").upper()
            inputs = [
                inp.get("name") for inp in form.find_all("input")
                if inp.get("name")
            ]

            self.forms.append({
                "page": current_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            })

    def extract_hidden_fields(self, current_url, soup):
        for inp in soup.find_all("input", type="hidden"):
            self.hidden_fields.append({
                "page": current_url,
                "name": inp.get("name"),
                "value": inp.get("value"),
            })

    def extract_inline_scripts(self, current_url, soup):
        for script in soup.find_all("script"):
            if not script.get("src") and script.string:
                self.inline_scripts.append({
                    "page": current_url,
                    "content": script.string.strip()[:200]  # snippet only
                })
