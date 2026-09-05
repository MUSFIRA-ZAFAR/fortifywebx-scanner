# FortifyWebX Scanner — User Guide

A complete walkthrough for installing, configuring, and running the scanner, plus fixes for the setup issues we actually ran into while building this.

---

## 1. Overview

FortifyWebX Scanner is a non-intrusive web application vulnerability scanner built for the FortifyWebX Week 5 internship capstone. It crawls a target, runs five passive vulnerability checks, and produces a scored Markdown/PDF report — with both a CLI and a web GUI.

**Scope reminder:** this tool is for authorized, non-production targets only — specifically **OWASP Juice Shop** and **DVWA** (Damn Vulnerable Web Application), or a mentor-assigned lab target. Never point it at a real or public website.

---

## 2. Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.9+ | `python3 --version` to check |
| pip | Usually bundled with Python |
| Docker | Used to run the test targets (Juice Shop / DVWA) |
| OS | **Ubuntu/Linux recommended.** See note below. |

**Why Linux over Windows/Kali:** This project is standard Python development (no offensive pentest toolkit needed), so a plain Ubuntu environment is the smoothest — Docker runs natively, and you avoid WSL2 networking quirks on Windows or the extra weight of Kali's pre-installed tooling. If you're on Windows, use WSL2 with an Ubuntu distro.

---

## 3. Installation

```bash
git clone <your-repo-url>
cd fortifywebx-scanner

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

**Disk space:** ~2–3 GB is comfortably enough (Docker engine + one target image + Python packages). If you pull both Juice Shop and DVWA, budget ~3–4 GB.

---

## 4. Setting Up a Test Target

### Option A — OWASP Juice Shop (recommended first target)

```bash
docker network create fortifywebx-net

docker run -d \
  --name fortifywebx-target \
  --network fortifywebx-net \
  -p 3000:3000 \
  bkimminich/juice-shop
```

Visit `http://localhost:3000` to confirm it's running.

### Option B — DVWA (Damn Vulnerable Web Application)

```bash
docker run -d \
  --name fortifywebx-dvwa \
  --network fortifywebx-net \
  -p 8080:80 \
  vulnerables/web-dvwa
```

First-time setup at `http://localhost:8080`:
1. Log in with default credentials: `admin` / `password`
2. Go to **Setup / Reset DB** → click **Create / Reset Database**
3. Log in again with the same credentials
4. Go to **DVWA Security** in the sidebar → set security level to **Low** (best for a first scan — findings decrease as you raise the level, which is an interesting comparison to try later)

**Why an isolated Docker network?** Running targets under their own `--network fortifywebx-net` keeps them separate from any other containers on your machine (e.g. a Wazuh setup or other lab VMs), so the scanner's traffic never touches anything unrelated.

---

## 5. Running the Scanner (CLI)

Basic usage:

```bash
python3 main.py -u http://localhost:3000
```

Or run without `-u` to be prompted interactively:

```bash
python3 main.py
Enter target URL: http://localhost:3000
```

**Available flags:**

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | *(prompts if omitted)* | Target URL to scan |
| `--delay` | `0.5` | Seconds between requests (rate limiting) |
| `--max-pages` | `30` | Maximum pages to crawl |

Example with custom rate limiting:

```bash
python3 main.py -u http://localhost:8080 --delay 1.0 --max-pages 15
```

The CLI prints colored, live findings as it scans, then saves both a Markdown and PDF report to `reports/`.

---

## 6. Running the Scanner (Web GUI)

```bash
python3 app.py
```

Open `http://localhost:5000` (or `http://127.0.0.1:5000`) in your browser.

1. Enter the target URL, optionally adjust delay/max pages
2. Click **Start Scan**
3. View the results dashboard: overall risk score, findings by severity, full details per finding
4. Download the Markdown or PDF report directly from the results page

---

## 7. Understanding the Report

### Risk Levels & Scoring

| Risk Level | Score | Meaning |
|---|---|---|
| High | 9 | Confirmed or strongly indicated vulnerability (e.g. leaked DB error text) |
| Medium | 6 | Real weakness, moderate impact (e.g. missing CSP/HSTS, insecure cookie) |
| Low | 3 | Minor hardening gap (e.g. missing X-Frame-Options) |
| Info | 1 | Worth a look, not necessarily a vulnerability (e.g. tech stack disclosed, unexplained 500 error) |

The **Overall Risk Score** is the sum of all finding scores — a simple, transparent way to compare scans of the same target over time, or compare two different targets.

### What Each Check Does

1. **Security Headers** — checks for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options` on every crawled page.
2. **Cookie Security** — inspects raw `Set-Cookie` headers for missing `HttpOnly`/`Secure` flags.
3. **XSS / Form Risk Patterns** — flags forms using GET with input, suspicious field names (`search`, `comment`, etc.), and POST forms with no apparent CSRF token. Pattern-based only — no payloads are ever sent.
4. **SQL Error Indicators** — scans response bodies for known database/ORM error text, and flags unexplained HTTP 500s as a lower-confidence signal. No injection payloads are sent.
5. **Tech Stack Fingerprinting** — reads `Server`/`X-Powered-By` headers only; no active probing.

---

## 8. Known Limitations

- **SPA form detection:** Juice Shop is an Angular single-page app. Its forms only exist after JavaScript renders them in a browser — a static HTML crawler (by design, non-intrusive, no headless browser) will report 0 forms on Juice Shop. This is documented, expected behavior, not a bug. (Verified separately via `tests/test_checks.py` against a static HTML fixture with real forms.)
- **No authentication support:** The crawler does not log in, so pages/endpoints requiring authentication (e.g. most of DVWA's vulnerability labs) are not scanned. A future enhancement would add session/cookie-based auth support.
- **Non-intrusive by design:** No exploitation is ever attempted. Some vulnerability classes (e.g. confirmed SQL injection) require manual, authorized follow-up beyond what this tool reports.
- **Known-endpoint fallback:** Since Juice Shop's real routes aren't discoverable via static crawling, a small hardcoded list of its known `/rest/` and `/api/` endpoints is used as additional seed URLs, so the checks still have real targets to test.

---

## 9. Project Structure

```
fortifywebx-scanner/
├── main.py                  # CLI entry point
├── app.py                   # Flask web GUI
├── requirements.txt
├── modules/
│   ├── crawler.py           # Module 2: recon & discovery
│   ├── checks.py            # Module 3: vulnerability checks
│   └── report_generator.py  # Module 4: MD + PDF report generation
├── templates/                # Web GUI HTML templates
├── tests/                     # Verification fixtures/scripts
├── docs/                       # This guide, sample reports, screenshots
└── reports/                     # Generated scan output (gitignored)
```

---

## 10. Troubleshooting

### Docker can't pull images — DNS "server misbehaving" error

**Symptom:**
```
docker: Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving
```

**Fix:** Point Docker's DNS explicitly:

```bash
sudo mkdir -p /etc/docker
sudo nano /etc/docker/daemon.json
```
```json
{ "dns": ["8.8.8.8", "1.1.1.1"] }
```
```bash
sudo systemctl restart docker
```

### VM has no internet at all / DNS times out even after the fix above

This usually means the VM's network adapter itself is misconfigured (e.g. stuck on a stale Bridged config after switching to NAT). Check:

```bash
ip addr show
```

- **NAT mode** should give you an address like `10.0.2.x`
- If you instead see your home router's subnet (e.g. `192.168.1.x`) after setting the adapter to NAT, the setting hasn't taken effect yet — **network adapter changes require a full VM power-off and restart**, not just a reboot inside the guest OS.

If a full restart still doesn't fix it, force a fresh DHCP lease and clear the stale IP manually:

```bash
sudo ip addr flush dev enp0s3
sudo ip link set enp0s3 down && sudo ip link set enp0s3 up
sudo dhclient enp0s3

# If the old IP persists alongside the new one:
sudo ip addr del <old_ip>/24 dev enp0s3
sudo ip route del default via <old_gateway>
sudo ip route add default via 10.0.2.2 dev enp0s3
```

### Flask: "Address already in use" / port 5000 stuck

```bash
sudo fuser -k 5000/tcp
python3 app.py
```

(`pkill app.py` doesn't work — `pkill` matches the actual process name, `python3`, not the script filename.)

### PDF export crashes: `FPDFException: Not enough horizontal space to render a single character`

Caused by long unbroken strings (e.g. URLs with no spaces) exceeding the page width, which FPDF can't wrap. Fixed in `report_generator.py` via `_safe_wrap()`, which measures actual rendered text width using FPDF's own font metrics and breaks long tokens character-by-character as needed.

### PDF export crashes: `FPDFUnicodeEncodingException`

Caused by Unicode punctuation (em dashes, curly quotes, ellipses) that the default Helvetica core font can't render (Latin-1 only). Fixed via `_sanitize_for_pdf()`, which maps common Unicode punctuation to ASCII equivalents before rendering.

### Crawler finds garbage/broken URLs in its queue

If you see mangled URLs like `/rest/products/\"https://github.com/...\"`, the crawler was parsing a **JSON or error-page response as if it were HTML**, misreading embedded text as links. Fixed by checking `Content-Type` and HTTP status code before running the HTML parser — JSON responses and 4xx/5xx error pages are recorded as discovered endpoints but never parsed for links.

### Scanner reports 0 forms on Juice Shop

Not a bug — see **Known Limitations** above. Verify the check logic itself works correctly by running:

```bash
cd tests
python3 test_checks.py
```

---

*This guide reflects the actual setup process used during development, including the real issues encountered and how they were resolved — not a hypothetical happy-path.*
