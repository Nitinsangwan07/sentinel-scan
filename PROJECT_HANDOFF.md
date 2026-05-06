# Sentinel Scan Project Handoff

Last updated: 2026-05-06  
Project path: `C:\Users\Nitin\Documents\Codex\sentinel-scan`  
Stack: Node.js, Express, Vanilla JavaScript, MongoDB/Mongoose, Render

## 1. Project Overview

Sentinel Scan is a passive, ethical web security scanning dashboard for authorized targets. It lets users create accounts, run low-impact scans against websites they are authorized to assess, review dashboard analytics, and export professional reports in PDF, TXT, Markdown, and JSON.

The current implementation is a production-style monolith:

- Express backend serves API routes and static frontend assets.
- Vanilla JavaScript frontend handles authentication, scanning, history, charts, filtering, and exports.
- MongoDB is the primary persistence layer through Mongoose.
- JSON fallback storage exists for local or demo environments where `MONGODB_URI` is not configured.
- Render deployment is supported through `render.yaml`.
- Docker and Docker Compose are present for containerized local development.

The scanner is intentionally passive. It does not exploit vulnerabilities, brute-force paths, fuzz parameters, launch denial-of-service checks, perform credential attacks, or run intrusive tests.

## 2. Full Project Architecture

High-level request flow:

```text
Browser UI
  -> public/app.js
  -> Express API routes
  -> Controllers
  -> Services
  -> Repositories
  -> MongoDB or JSON fallback
```

Scanning flow:

```text
POST /api/scans
  -> authenticate JWT
  -> scanController.createScan
  -> scanService.executeScan
  -> scanner.scanWebsite
  -> aiAssistService.buildAiAssist
  -> scanRepository.create
  -> MongoDB Scan document or fallback JSON record
  -> JSON response to dashboard
```

Report flow:

```text
GET /api/reports/:scanId/:format
  -> authenticate JWT
  -> reportController.downloadReport
  -> scanService.getUserScanById
  -> reportService.exportReport
  -> reportRepository.create
  -> streamed/downloaded file response
```

Auth flow:

```text
Local signup/login:
  -> /api/auth/signup or /api/auth/login
  -> authService
  -> bcrypt password hashing/comparison
  -> JWT issued
  -> frontend stores token

Google login:
  -> Google Identity Services in browser
  -> /api/auth/google receives ID token
  -> google-auth-library verifies token
  -> user is found or created
  -> JWT issued
```

## 3. Folder Structure Explanation

```text
sentinel-scan/
  .github/workflows/
    ci.yml
  data/
    fallback/
      store.json
  public/
    app.js
    favicon.svg
    index.html
    styles.css
  src/
    config/
    controllers/
    lib/
    middleware/
    models/
    repositories/
    routes/
    services/
    utils/
    app.js
    server.js
  .dockerignore
  .env.example
  .gitignore
  Dockerfile
  docker-compose.yml
  package.json
  package-lock.json
  README.md
  render.yaml
  SECURITY.md
```

Important folders:

- `src/config`: environment and database configuration.
- `src/controllers`: request/response handlers.
- `src/routes`: Express route definitions.
- `src/services`: business logic for auth, scans, reports, AI-style explanations, and fallback storage.
- `src/repositories`: persistence abstraction for MongoDB and JSON fallback.
- `src/models`: Mongoose schemas for users, scans, and reports.
- `src/middleware`: authentication, validation, rate limiting, error handling, and 404 handling.
- `src/lib`: passive scan engine and legacy JSON storage helper.
- `src/utils`: shared helpers for async handlers, JWT/password auth, and HTTP errors.
- `public`: browser app, styling, markup, and favicon.
- `.github/workflows`: CI syntax-check pipeline.

## 4. Backend Flow

Backend entry points:

- `src/server.js`: connects database and starts HTTP server.
- `src/app.js`: creates the Express app, registers middleware, static hosting, API routes, SPA fallback, and error handlers.

Backend middleware:

- `helmet`: HTTP security headers and CSP rules.
- `cors`: CORS configuration from `CORS_ORIGIN`.
- `express-rate-limit`: global request limiting.
- `authRateLimiter`: stricter limiter for auth routes.
- `express.json`: JSON request parsing.
- `authenticate`: Bearer JWT validation for protected APIs.
- `validateRequiredFields`: minimal request field validation.
- `errorHandler`: JSON error responses.
- `notFoundHandler`: API 404 handling.

Backend service boundaries:

- `authService`: signup, login, Google login, password validation, JWT issuance.
- `scanService`: normalizes scan options, runs the scanner, stores scan records, returns history metrics.
- `reportService`: creates PDF/TXT/Markdown/JSON exports and stores report records.
- `aiAssistService`: heuristic simple-language summary and remediation notes.
- `fallbackStoreService`: JSON fallback persistence for environments without MongoDB.

## 5. Frontend Flow

Main frontend files:

- `public/index.html`: dashboard markup and Google Identity Services script include.
- `public/styles.css`: responsive premium dashboard styling.
- `public/app.js`: full client-side application logic.
- `public/favicon.svg`: simple product icon.

Frontend startup sequence:

1. Read `sentinelToken` from `localStorage` or `sessionStorage`.
2. Load auth config from `/api/auth/config`.
3. Initialize Google sign-in button if `GOOGLE_CLIENT_ID` is configured.
4. Attempt session restoration through `/api/auth/me` if a token exists.
5. Show dashboard if token is valid.
6. Show login/signup panel if token is absent or invalid.

Core frontend responsibilities:

- Local login/signup forms.
- Optional Google sign-in.
- JWT storage and logout cleanup.
- Target scan form with authorization confirmation.
- Scan progress messaging and loading skeletons.
- Saved scan history.
- Severity chart.
- Risk trend chart.
- Recent activity feed.
- Summary report panel.
- Compact remediation memo.
- Findings search/filter.
- Coverage and asset inventory.
- PDF/TXT/Markdown/JSON/HTML downloads.

## 6. Authentication System

Local authentication:

- Endpoint: `POST /api/auth/signup`
- Endpoint: `POST /api/auth/login`
- Password hashing: `bcryptjs`
- Password minimum length: 8 characters
- Duplicate email prevention: `userRepository.findByEmail`
- JWT issuance: `jsonwebtoken`
- JWT subject: user ID in `sub`

Google authentication:

- Endpoint: `GET /api/auth/config`
- Endpoint: `POST /api/auth/google`
- Browser service: Google Identity Services
- Backend verifier: `google-auth-library`
- Required environment variable: `GOOGLE_CLIENT_ID`
- Behavior: verifies Google ID token, finds user by `googleId`, links existing email account when appropriate, or creates a new Google user.

Session behavior:

- Frontend stores JWT in `localStorage` by default.
- Frontend also checks `sessionStorage` for compatibility.
- Logout clears `localStorage`, `sessionStorage`, and common auth cookie names.
- Protected routes require `Authorization: Bearer <token>`.
- Invalid or expired tokens cause frontend session reset.

Important auth files:

- `src/services/authService.js`
- `src/controllers/authController.js`
- `src/routes/authRoutes.js`
- `src/middleware/authMiddleware.js`
- `src/utils/auth.js`
- `src/models/User.js`
- `public/app.js`

## 7. MongoDB Schema And Models

### User Model

File: `src/models/User.js`

Fields:

- `name`: required string, trimmed, 2-80 chars.
- `email`: required unique lowercase string, indexed.
- `passwordHash`: string or null.
- `authProvider`: `local` or `google`.
- `googleId`: sparse unique Google subject ID.
- Mongoose timestamps: `createdAt`, `updatedAt`.

### Scan Model

File: `src/models/Scan.js`

Top-level fields:

- `userId`: ObjectId ref `User`, required, indexed.
- `target`: submitted target URL.
- `finalUrl`: final URL after redirects.
- `scannedAt`: required date, indexed.
- `durationMs`: scan duration.
- `options`: crawl and timeout settings.
- `risk`: score and band.
- `summary`: total findings, severity counts, category counts.
- `findings`: embedded finding documents.
- `coverage`: crawl pages and page count.
- `inventory`: forms, password surfaces, script hosts, login pages, sensitive files.
- `transport`: TLS inspection result.
- `auxiliaryFiles`: `security.txt`, `robots.txt`, `sitemap.xml` checks.
- `sensitiveFiles`: sensitive-file probe results.
- `report`: executive summary, narrative, priority actions.
- `markdown`: generated Markdown report.
- `aiAssist`: heuristic explanation data.
- Mongoose timestamps.

Finding fields:

- `id`
- `title`
- `severity`
- `score`
- `category`
- `description`
- `impact`
- `remediation`
- `evidence`
- `location`
- `confidence`
- `confidenceLabel`
- `affectedUrls`

Indexes:

- `userId`
- `target`
- `scannedAt`
- `findings.severity`
- `findings.category`
- compound `{ userId: 1, scannedAt: -1 }`

### Report Model

File: `src/models/Report.js`

Fields:

- `userId`: ObjectId ref `User`, indexed.
- `scanId`: ObjectId ref `Scan`, indexed.
- `format`: `pdf`, `txt`, `md`, or `json`.
- `fileName`
- `sizeBytes`
- `content`: base64 for PDF, text for text formats.
- Mongoose timestamps.

Index:

- compound `{ userId: 1, scanId: 1, createdAt: -1 }`

## 8. API Routes And Endpoints

Base health route:

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/health` | No | Returns service status, version, storage mode, and auth config indicator. |

Auth routes:

| Method | Endpoint | Auth | Body | Description |
| --- | --- | --- | --- | --- |
| GET | `/api/auth/config` | No | none | Returns Google auth availability and client ID. |
| POST | `/api/auth/signup` | No | `name`, `email`, `password` | Creates a local account and returns JWT. |
| POST | `/api/auth/login` | No | `email`, `password` | Logs in a local account and returns JWT. |
| POST | `/api/auth/google` | No | `idToken` | Verifies Google ID token and returns JWT. |
| GET | `/api/auth/me` | Yes | none | Returns current authenticated user. |

Scan routes:

| Method | Endpoint | Auth | Body | Description |
| --- | --- | --- | --- | --- |
| GET | `/api/scans` | Yes | none | Lists user-specific scan summaries and metrics. |
| POST | `/api/scans` | Yes | `url`, optional `options` | Runs passive scan and stores full result. |
| GET | `/api/scans/:scanId` | Yes | none | Returns a full scan owned by the user. |
| GET | `/api/scans/:scanId/ai` | Yes | none | Returns AI-style heuristic remediation notes. |

Report routes:

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/reports/:scanId/pdf` | Yes | Downloads PDF report. |
| GET | `/api/reports/:scanId/txt` | Yes | Downloads TXT report. |
| GET | `/api/reports/:scanId/md` | Yes | Downloads Markdown report. |
| GET | `/api/reports/:scanId/json` | Yes | Downloads JSON report. |

## 9. Environment Variables

Defined in `.env.example`:

```env
PORT=3000
NODE_ENV=development
MONGODB_URI=
JWT_SECRET=change-me
JWT_EXPIRES_IN=8h
CORS_ORIGIN=*
GOOGLE_CLIENT_ID=
AI_PROVIDER=heuristic
AI_API_KEY=
AI_API_URL=
```

Variable notes:

- `PORT`: Express server port.
- `NODE_ENV`: runtime mode.
- `MONGODB_URI`: MongoDB Atlas or local Mongo connection string. If absent, app uses JSON fallback.
- `JWT_SECRET`: signing secret for JWTs. Must be strong in production.
- `JWT_EXPIRES_IN`: JWT lifetime passed to `jsonwebtoken`.
- `CORS_ORIGIN`: `*` or a specific deployed frontend origin.
- `GOOGLE_CLIENT_ID`: enables Google sign-in.
- `AI_PROVIDER`: currently `heuristic`; reserved for future provider integration.
- `AI_API_KEY`: reserved for future external AI provider.
- `AI_API_URL`: reserved for future external AI provider endpoint.

## 10. Deployment Configuration

### Render

File: `render.yaml`

Current Render service:

- Type: `web`
- Environment: `node`
- Build command: `npm install`
- Start command: `npm start`
- Plan: `free`

Required Render environment variables:

- `NODE_ENV=production`
- `JWT_SECRET`
- `MONGODB_URI`
- `CORS_ORIGIN`

Optional Render environment variable:

- `GOOGLE_CLIENT_ID`

Recommended Render setup:

1. Create MongoDB Atlas cluster.
2. Add Render outbound IPs to Atlas network access, or temporarily use `0.0.0.0/0` for development only.
3. Create a MongoDB database user.
4. Set `MONGODB_URI` in Render.
5. Set a strong `JWT_SECRET`.
6. Set `CORS_ORIGIN` to the Render service URL.
7. If Google auth is used, add Render domain to Google OAuth allowed JavaScript origins and set `GOOGLE_CLIENT_ID`.
8. Deploy from GitHub.

### MongoDB Atlas

Atlas requirements:

- Cluster available to Render.
- Database user with read/write access.
- Connection string configured as `MONGODB_URI`.
- TLS supported by default.

The app uses Mongoose with `autoIndex: true`, so indexes are created from schemas in active environments.

### Docker

`Dockerfile`:

- Uses `node:20-alpine`.
- Runs `npm ci --omit=dev`.
- Exposes port `3000`.
- Starts with `npm start`.

`docker-compose.yml`:

- Runs app and local `mongo:7`.
- Maps app to `3000:3000`.
- Maps Mongo to `27017:27017`.
- Uses `.env`.
- Persists Mongo data in `mongo-data` volume.

## 11. Scan Engine Logic

Main file: `src/lib/scanner.js`

Core exported functions:

- `normalizeScanOptions(options)`
- `scanWebsite(target, requestedOptions)`

Default scan options:

- `includeSubpages: true`
- `maxPages: 6`
- hard clamp up to 10 pages
- `requestTimeoutMs: 12000`

High-level scan steps:

1. Fetch submitted target with passive GET.
2. Record final URL after redirects.
3. Analyze primary response headers.
4. Parse cookies from response.
5. Crawl same-origin pages up to configured limit.
6. Inspect HTTP to HTTPS redirect behavior.
7. Fetch auxiliary files:
   - `/.well-known/security.txt`
   - `/robots.txt`
   - `/sitemap.xml`
8. Fetch sensitive-file paths:
   - `/.env`
   - `/.git/HEAD`
   - `/.git/config`
   - `/backup.zip`
   - `/config.php.bak`
   - `/config.json`
   - `/debug.log`
   - `/server-status`
9. Inspect TLS certificate/protocol for HTTPS targets.
10. Build findings.
11. Sort findings by severity weight.
12. Group findings by severity and category.
13. Calculate risk score.
14. Build narrative and Markdown report.
15. Return complete scan object.

Passive checks currently implemented or partially implemented:

- Missing or permissive CSP.
- Missing HSTS.
- Weak HSTS max-age.
- Wildcard CORS.
- Exposed `Server` or `X-Powered-By` banners.
- Insecure cookie flags:
  - missing `Secure`
  - missing `HttpOnly`
  - missing `SameSite`
- Password form over HTTP.
- Insecure form action from HTTPS to HTTP.
- Possible missing CSRF token markers.
- Heavy inline script usage.
- Risky inline JavaScript pattern detection.
- Mixed-content references.
- Heavy third-party script reliance.
- Third-party scripts on password pages.
- Raw/user-generated script hosts.
- Links using `target=_blank` without rel protections.
- Outdated JavaScript library references for known filename patterns.
- Generator metadata.
- Suspicious HTML comments.
- Source map reference patterns.
- API/token regex patterns.
- Firebase configuration exposure pattern.
- Cloud storage exposure pattern.
- Directory listing pattern.
- Sensitive-looking routes.
- `security.txt` missing.
- `robots.txt` sensitive path disclosure.
- `sitemap.xml` missing.
- Public sensitive files.
- TLS handshake failure.
- Certificate trust issue.
- Legacy TLS protocol.
- Certificate expiry.
- HTTP without HTTPS upgrade.
- HTTP endpoint reachable without redirect.

Important limitations of scan logic:

- It is heuristic.
- It has no JavaScript rendering or browser automation.
- It does not authenticate into target applications.
- It does not deeply parse source maps.
- It does not inspect JavaScript bundle contents beyond HTML/script references.
- It does not check package CVEs through an external vulnerability database.
- It does not perform path brute forcing.

## 12. Report Generation Logic

Main file: `src/services/reportService.js`

Supported export formats:

- `pdf`
- `txt`
- `md`
- `json`

Report generation flow:

1. User requests report download.
2. Backend verifies ownership of scan.
3. `reportService.exportReport` validates format.
4. File content is generated from stored scan data.
5. Report metadata/content is stored through `reportRepository`.
6. API sends file response with `Content-Disposition: attachment`.

PDF implementation:

- Uses `pdfkit`.
- Creates a branded header.
- Includes executive summary.
- Includes scan metadata.
- Draws severity bars.
- Lists priority recommendations.
- Adds findings overview cards.
- Adds page footer numbers.
- Stores base64 PDF content in `Report` collection.

Text and Markdown implementation:

- Includes metadata.
- Includes executive summary.
- Includes severity breakdown.
- Includes recommendations.
- Includes findings with severity, confidence, category, affected URL, evidence, impact, and remediation.

JSON implementation:

- Includes metadata, risk, summary, report narrative, findings, inventory, and scope.

## 13. Current Implemented Features

Authentication:

- Local signup.
- Local login.
- JWT sessions.
- Password hashing with bcrypt.
- Duplicate email protection.
- Optional Google sign-in.
- Session restore on page refresh.
- Logout cleanup across storage/cookies.

Scanning:

- Passive target analysis.
- Same-origin crawling.
- TLS inspection.
- Header review.
- Cookie review.
- HTML/form/script analysis.
- Auxiliary file checks.
- Sensitive public file checks.
- Risk score.
- Severity/category summaries.
- Confidence metadata in findings.

Dashboard:

- Responsive premium UI.
- Light/dark theme.
- Scan form with authorization confirmation.
- Loading states and progress text.
- Total scans.
- Average risk.
- Current risk.
- Risk band.
- Duration.
- Pages crawled.
- Findings count.
- Top category.
- Severity chart.
- Risk trend chart.
- Recent activity.
- Scan history.
- Findings search and filters.
- Coverage inventory.
- Compact remediation memo.

Exports:

- PDF download.
- TXT download.
- Markdown download.
- JSON download.
- Client-side HTML snapshot download.

DevOps:

- Render config.
- Dockerfile.
- Docker Compose.
- GitHub Actions syntax-check workflow.

## 14. Current Known Limitations

- Scanner is passive and heuristic by design, so all findings require manual validation.
- No authenticated target scanning.
- No target ownership verification beyond user confirmation checkbox.
- No scan job queue; scan runs inside the HTTP request lifecycle.
- No real-time server-side scan progress events.
- No browser rendering for single-page apps.
- No advanced HTML parser library; scanner mostly uses regex/string heuristics.
- No external vulnerability intelligence feed.
- No external AI provider integration yet.
- JSON fallback is not suitable for production persistence.
- Reports are generated on demand and stored in database, but there is no report management UI.
- No automated test suite beyond syntax checks.
- Google auth requires correct Google Cloud configuration and `GOOGLE_CLIENT_ID`.
- Existing `public/new.env` contains a development JWT secret and should not be used as production configuration.
- Some repository states may include accidental local `node_modules` tracking from earlier work; `.gitignore` should prevent future adds.

## 15. Pending Bugs And Issues

Highest priority issues to check next:

- Run a full local HTTP smoke test after setting a clean `.env`, because previous live process checks were limited by local sandbox process-launch behavior.
- Verify Google sign-in end to end on localhost and Render with a real Google OAuth client.
- Confirm PDF generation with real scans containing many findings; ensure long evidence text does not overflow cards.
- Review `src/lib/scanner.js` for scanner false positives after several real-world targets.
- Remove or secure `public/new.env`; public env-like files should not contain secrets, even development secrets.
- Add validation for report `format` route param before reaching service-level export.
- Add stronger URL validation to prevent internal network scanning if this is exposed publicly.
- Add test coverage for auth, scan ownership, report ownership, and repository fallback behavior.
- Confirm Mongo ObjectId handling for JSON fallback versus Mongo records after Google account linking.

## 16. Suggested Future Improvements

Scanner:

- Add a scan queue with job IDs.
- Add Server-Sent Events or WebSocket scan progress.
- Add Playwright-based optional rendered-page passive mode.
- Add sitemap URL ingestion.
- Add robots path prioritization without brute force.
- Add JavaScript bundle fetch and passive token/source-map analysis.
- Add npm/CDN version intelligence backed by a maintained advisory source.
- Add configurable scan profiles.

Security:

- Add strict SSRF protection and private IP blocking.
- Add account email verification.
- Add password reset.
- Add refresh-token rotation or short-lived access token model.
- Add audit logs.
- Add organization/team support.
- Add per-user rate limits and scan quotas.

Product:

- Add report history UI.
- Add scan comparison.
- Add finding status workflow:
  - open
  - accepted risk
  - fixed
  - false positive
- Add comments/notes on findings.
- Add project/workspace grouping.
- Add CSV export.
- Add branded report customization.

Testing:

- Add unit tests for services.
- Add integration tests for API routes.
- Add frontend smoke tests.
- Add sample fixture sites for scanner regression tests.
- Add CI test matrix for Node 20 and current LTS.

## 17. UI/UX Design Philosophy

The current UI direction is calm, compact, and professional. It is intended to feel like a cybersecurity operations dashboard rather than a marketing landing page or student demo.

Design principles:

- Put the usable dashboard first.
- Keep copy short and operational.
- Avoid flashy hacker aesthetics.
- Use neutral light surfaces with restrained dark mode.
- Prefer compact metrics and scanning workflows.
- Keep detailed explanations in downloadable reports.
- Show summarized findings in the dashboard.
- Make actions obvious:
  - scan
  - filter
  - load history
  - export report
  - logout
- Avoid overly long page sections.
- Keep mobile and tablet layouts readable.
- Prevent text overflow in cards and tables.

Current visual language:

- Soft neutral background.
- Teal/green accent for trust and action.
- Severity colors:
  - critical: red
  - high: orange
  - medium: amber
  - low: green
  - info: blue
- Rounded panels and cards.
- Subtle hover transitions.
- Skeleton loading states.
- Lightweight CSS charts.

## 18. Security Considerations

Application security:

- Uses Helmet with CSP configured for self, Google Identity Services, Google fonts, and required image/font/connect sources.
- Disables `X-Powered-By`.
- Uses CORS configuration from environment.
- Uses rate limiting globally and stricter auth route limiting.
- Hashes local passwords with bcrypt.
- Uses JWT bearer tokens for protected APIs.
- Enforces user-specific scan/report access in backend services.
- Stores Google login users without a password hash.

Scanner safety:

- Passive GET-based checks only.
- No exploitation.
- No brute forcing.
- No fuzzing.
- No denial-of-service behavior.
- No credential attacks.
- No destructive requests.

Security work still recommended:

- Add SSRF protection before public production use.
- Block private/reserved/link-local IP targets.
- Add scan quotas.
- Add audit logs.
- Move any public dev secrets out of `public`.
- Use a strong `JWT_SECRET`.
- Set `CORS_ORIGIN` to the exact Render domain in production.
- Keep MongoDB Atlas access restricted.
- Validate Google OAuth origins.

## 19. Third-Party Services Used

Runtime services:

- MongoDB Atlas: recommended production database.
- Render: Node web service deployment.
- Google Identity Services: browser Google sign-in.
- Google OAuth token verification: backend ID token verification.

Development/CI:

- GitHub: repository and Render deployment source.
- GitHub Actions: syntax-check CI.
- Docker: optional container runtime.
- Docker Compose: optional local app plus Mongo.

## 20. Package And Dependency Overview

Production dependencies:

- `express`: web framework.
- `mongoose`: MongoDB object modeling.
- `jsonwebtoken`: JWT creation and verification.
- `bcryptjs`: password hashing and comparison.
- `helmet`: HTTP security headers and CSP.
- `cors`: CORS middleware.
- `express-rate-limit`: request throttling.
- `dotenv`: environment variable loading.
- `pdfkit`: PDF report generation.
- `google-auth-library`: Google ID token verification.

Scripts:

```json
{
  "start": "node src/server.js",
  "dev": "node --watch src/server.js",
  "check": "node --check src/server.js && node --check public/app.js"
}
```

Node requirement:

- Node.js `>=20`

## 21. Recommended Next Development Priorities

Priority 1:

- Run full local smoke tests against MongoDB Atlas and JSON fallback.
- Verify signup, login, logout, refresh restore, and `/api/auth/me`.
- Verify Google sign-in with real `GOOGLE_CLIENT_ID`.
- Verify report downloads for all formats.
- Remove or neutralize `public/new.env`.

Priority 2:

- Add SSRF protection and private IP blocking.
- Move scans into a background job model.
- Add server-side scan progress events.
- Add tests for auth ownership and report access.

Priority 3:

- Add report history UI.
- Add scan comparison and trend analysis.
- Add finding lifecycle management.
- Add rendered-page passive mode for modern SPAs.

Priority 4:

- Integrate a real AI provider behind `aiAssistService`.
- Add organization/team support.
- Add branded customer-ready report templates.

## 22. Quick Start For Next Developer

Install dependencies:

```bash
npm install
```

Create `.env`:

```bash
cp .env.example .env
```

Minimum local `.env`:

```env
PORT=3000
NODE_ENV=development
JWT_SECRET=replace-with-a-long-random-secret
MONGODB_URI=
CORS_ORIGIN=*
```

Run with JSON fallback:

```bash
npm start
```

Run with Docker Compose:

```bash
docker compose up --build
```

Open:

```text
http://localhost:3000
```

Run syntax checks:

```bash
npm run check
```

## 23. Continuation Notes For Another AI Model

Do not rebuild the project from scratch. Continue within the existing architecture:

- Keep Express.
- Keep Vanilla JS.
- Keep MongoDB/Mongoose.
- Keep Render deployment.
- Keep passive-only scanning.
- Preserve user-specific scan ownership.
- Prefer scoped changes over broad rewrites.

When improving scanner quality, focus on reducing false positives, adding evidence quality, and improving passive analysis depth. Avoid adding active attack behavior.

When improving UI, keep the dashboard compact, operational, and professional. Avoid turning it into a long landing page.

When improving auth, keep JWT compatibility and avoid breaking existing local accounts.

