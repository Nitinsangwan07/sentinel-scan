# Sentinel Scan

Sentinel Scan is a professional passive web security scanning dashboard for authorized website reviews. It inspects public-facing web security posture, inventories attack surface clues, stores user-specific scan history, and generates exportable remediation reports without performing exploitative or intrusive actions.

## Features

- Passive-only web security analysis for authorized targets
- JWT-based signup and login
- Express API with modular controllers, routes, middleware, and services
- MongoDB-ready persistence with indexed Mongoose schemas
- Safe local JSON fallback when `MONGODB_URI` is not configured
- Report export in PDF, TXT, Markdown, and JSON
- AI-assisted simple-language remediation notes
- Severity pie chart and risk trend visualization
- Responsive cybersecurity-style dashboard with dark and light themes
- Rate limiting, Helmet, CORS controls, and structured error handling

## Screenshots

- Add dashboard screenshots here after deployment:
  - `docs/screenshots/login.png`
  - `docs/screenshots/dashboard.png`
  - `docs/screenshots/report-export.png`

## Security Disclaimer

Sentinel Scan is designed for educational and defensive security purposes only.

- Use it only on systems you own or are explicitly authorized to assess.
- The scanner is intentionally passive and low impact.
- It does not exploit vulnerabilities, brute-force content, fuzz endpoints, or attempt denial-of-service behavior.
- Findings are heuristic and should always be manually validated.

## Architecture Overview

```text
public/
  index.html            Frontend shell
  app.js                Dashboard logic, auth, charts, exports
  styles.css            Responsive cybersecurity UI

src/
  app.js                Express app assembly
  server.js             Startup entrypoint
  config/               Environment and database configuration
  controllers/          Route handlers
  middleware/           Auth, rate limiting, validation, error handling
  models/               Mongoose schemas
  repositories/         Mongo and fallback persistence access
  routes/               Express route modules
  services/             Scan orchestration, reports, auth, AI notes
  utils/                Shared helpers
  lib/                  Existing passive scan engine and legacy helpers
```

## Installation

### Prerequisites

- Node.js 20+
- MongoDB connection string for production-grade persistence

### 1. Install dependencies

```bash
npm install
```

### 2. Create environment variables

Copy `.env.example` to `.env` and configure:

```env
PORT=3000
NODE_ENV=development
MONGODB_URI=mongodb://127.0.0.1:27017/sentinel-scan
JWT_SECRET=replace-this-with-a-strong-secret
JWT_EXPIRES_IN=8h
CORS_ORIGIN=*
AI_PROVIDER=heuristic
AI_API_KEY=
AI_API_URL=
```

### 3. Start the app

```bash
npm start
```

Open [http://localhost:3000](http://localhost:3000).

## Docker

### Run with Docker Compose

```bash
docker-compose up --build
```

This starts:

- the Sentinel Scan app on port `3000`
- MongoDB on port `27017`

## API Documentation

### Auth

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`

### Scans

- `GET /api/scans`
- `POST /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/scans/:scanId/ai`

### Reports

- `GET /api/reports/:scanId/pdf`
- `GET /api/reports/:scanId/txt`
- `GET /api/reports/:scanId/md`
- `GET /api/reports/:scanId/json`

### Health

- `GET /api/health`

## Passive Security Checks

Sentinel Scan focuses on passive observations such as:

- HTTPS redirect posture
- TLS certificate and version posture
- Missing or weak HSTS
- Insecure cookie attributes
- Exposed server banners
- Weak CSP patterns
- Mixed content references
- Directory indexing patterns
- Suspicious login and admin route discovery
- Insecure form actions
- Outdated JavaScript libraries and frontend frameworks
- Weak CORS behavior
- Missing CSRF hints
- Third-party script risk analysis
- Security.txt, robots.txt, sitemap, and metadata leakage checks
- Publicly exposed sensitive file paths

## Local Development Notes

- When `MONGODB_URI` is present, Sentinel Scan uses MongoDB through Mongoose.
- When `MONGODB_URI` is missing, the app falls back to `data/fallback/store.json` so local development and demos can still run.
- Report exports are stored as report records so user activity remains auditable.

## GitHub + Render Redeploy

### 1. Push to GitHub

Commit and push your changes:

```bash
git add .
git commit -m "Upgrade Sentinel Scan platform"
git push origin main
```

### 2. Configure Render

In Render, point your existing web service to this repository and set:

- `Build Command`: `npm install`
- `Start Command`: `npm start`

Set these environment variables in Render:

- `NODE_ENV=production`
- `JWT_SECRET=<strong-random-secret>`
- `MONGODB_URI=<your-mongo-connection-string>`
- `CORS_ORIGIN=<your-render-domain-or-custom-domain>`

### 3. Deploy

- If auto-deploy is enabled, Render will deploy after push.
- Otherwise, use `Manual Deploy` on the latest commit.

The included `render.yaml` can also be used as a starting point for infrastructure-as-code style setup.

## CI/CD

GitHub Actions runs a lightweight syntax verification workflow on pushes and pull requests:

- installs dependencies with `npm ci`
- runs `node --check` across the `src/` and `public/` JavaScript files

## Notes

- This project keeps the original vanilla JavaScript frontend and a Render-friendly Node.js start path.
- The scanner remains passive and avoids exploitative behavior by design.
- Findings are heuristic and should be manually validated before remediation or disclosure decisions.
