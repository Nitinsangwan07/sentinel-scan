# Sentinel Scan

Sentinel Scan is an AI-assisted web security scanning platform for authorized website reviews. It performs passive checks against a target website, crawls a small same-origin page set for broader visibility, saves scan history, and produces remediation-focused reports for engineering teams.

## Current features

- Passive checks for HTTPS/TLS posture, certificate trust, and redirect policy
- Security header analysis, including weak CSP, weak HSTS, and wildcard CORS
- Cookie hardening checks for `Secure`, `HttpOnly`, and `SameSite`
- HTML and form heuristics such as password-over-HTTP, mixed content, and CSRF token hints
- Limited same-origin crawl with per-page inventory
- External script host inventory and lightweight technology fingerprinting
- Saved scan history with reloadable reports
- JSON, Markdown, and HTML report export

## Safety model

This project is intentionally scoped to passive, low-impact checks for sites you are authorized to assess. It does not attempt exploitation, brute-force discovery, content fuzzing, or authenticated attacks.

## Run locally

```bash
npm start
```

Then open `http://localhost:3000`.

## API

- `GET /api/health`: health check
- `GET /api/scans`: list saved scan summaries
- `GET /api/scans/:id`: load a saved full scan
- `POST /api/scan`: run and persist a new scan

Example request body:

```json
{
  "url": "https://example.com",
  "options": {
    "includeSubpages": true,
    "maxPages": 4
  }
}
```

## Project structure

- `src/server.js`: HTTP server and JSON API
- `src/lib/scanner.js`: passive scan engine, crawler, and report generation
- `src/lib/storage.js`: JSON-backed scan persistence
- `public/`: dashboard UI
- `data/scans.json`: saved scan history

## Notes

- Results are heuristic and should be validated manually.
- Some websites may block automated requests or require authentication, which will limit coverage.
