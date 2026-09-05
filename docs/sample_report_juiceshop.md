# FortifyWebX Scan Report

**Target:** http://localhost:3000
**Scan Date:** 2026-09-02 06:56:00
**Overall Risk Score:** 98

## Crawl Summary

- Pages discovered: 8
- Forms discovered: 0 *(see Known Limitations — Juice Shop renders forms client-side via Angular)*
- Hidden fields discovered: 0
- Inline scripts discovered: 1

## Findings Summary

| Risk Level | Count | Score Each |
|---|---|---|
| High | 0 | 9 |
| Medium | 16 | 6 |
| Low | 0 | 3 |
| Info | 2 | 1 |
| **Total Findings** | **18** | **Risk Score: 98** |

## Medium Risk Findings (16)

### 1. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 2. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 3. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/rest/products
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 4. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/rest/products
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 5. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/rest/user/login
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 6. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/rest/user/login
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 7. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/rest/user/whoami
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 8. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/rest/user/whoami
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 9. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/api/Users
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 10. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/api/Users
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 11. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/api/Feedbacks
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 12. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/api/Feedbacks
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 13. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/rest/basket
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 14. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/rest/basket
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

### 15. Missing Security Header: Content-Security-Policy (Score: 6)
- **Location:** http://localhost:3000/rest/products/search
- **Evidence:** Header 'Content-Security-Policy' not present in response.
- **Description:** Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.

### 16. Missing Security Header: Strict-Transport-Security (Score: 6)
- **Location:** http://localhost:3000/rest/products/search
- **Evidence:** Header 'Strict-Transport-Security' not present in response.
- **Description:** Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.

## Info Risk Findings (2)

### 1. Server Error (HTTP 500) on Request (Score: 1)
- **Location:** http://localhost:3000/rest/products
- **Evidence:** Endpoint returned HTTP 500 with no recognized DB error pattern in body.
- **Description:** Unhandled server error. Not confirmed as DB-related, but worth manual review - error handling gaps can sometimes leak sensitive info depending on debug settings.

### 2. Server Error (HTTP 500) on Request (Score: 1)
- **Location:** http://localhost:3000/rest/user/login
- **Evidence:** Endpoint returned HTTP 500 with no recognized DB error pattern in body.
- **Description:** Unhandled server error. Not confirmed as DB-related, but worth manual review - error handling gaps can sometimes leak sensitive info depending on debug settings.

---
*Report generated by FortifyWebX Scanner - non-intrusive scan only, no exploitation attempted.*
