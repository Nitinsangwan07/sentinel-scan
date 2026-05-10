import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { authRateLimiter } from "./middleware/rateLimiters.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { notFoundHandler } from "./middleware/notFoundHandler.js";
import authRoutes from "./routes/authRoutes.js";
import reportRoutes from "./routes/reportRoutes.js";
import scanRoutes from "./routes/scanRoutes.js";
import { appConfig } from "./config/env.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, "../public");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

function resolveCorsOrigin() {
  if (!appConfig.corsOrigin || appConfig.corsOrigin === "*") {
    return appConfig.isProduction ? false : true;
  }

  const origins = appConfig.corsOrigin
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

  return origins.length === 1 ? origins[0] : origins;
}

function getRequestBaseUrl(request) {
  const forwardedProto = request.headers["x-forwarded-proto"]?.split(",")?.[0]?.trim();
  const protocol = forwardedProto || request.protocol || "https";
  return `${protocol}://${request.get("host")}`;
}

const cspDirectives = {
  defaultSrc: ["'self'"],
  baseUri: ["'self'"],
  scriptSrc: ["'self'", "https://accounts.google.com", "https://apis.google.com"],
  styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://accounts.google.com"],
  fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
  imgSrc: ["'self'", "data:", "https:"],
  connectSrc: [
    "'self'",
    "https://accounts.google.com",
    "https://oauth2.googleapis.com",
    "https://www.googleapis.com",
    "https://*.googleapis.com",
  ],
  frameSrc: ["'self'", "https://accounts.google.com", "https://content.googleapis.com"],
  frameAncestors: ["'self'"],
  formAction: ["'self'", "mailto:"],
  objectSrc: ["'none'"],
};

if (appConfig.isProduction) {
  cspDirectives.upgradeInsecureRequests = [];
}

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
    hsts: appConfig.isProduction
      ? {
          maxAge: 15552000,
          includeSubDomains: true,
          preload: false,
        }
      : false,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    contentSecurityPolicy: {
      useDefaults: false,
      directives: cspDirectives,
    },
  }),
);

app.use(
  cors({
    origin: resolveCorsOrigin(),
    credentials: true,
  }),
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 250,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: "Too many requests. Please try again in a few minutes.",
    },
  }),
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

app.get("/.well-known/security.txt", (request, response) => {
  const baseUrl = getRequestBaseUrl(request);
  const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

  response.type("text/plain").send([
    "Contact: mailto:gamerbuddy9090@gmail.com",
    `Policy: ${baseUrl}/terms.html`,
    `Canonical: ${baseUrl}/.well-known/security.txt`,
    "Preferred-Languages: en",
    `Expires: ${expires}`,
    "",
  ].join("\n"));
});

app.get("/sitemap.xml", (request, response) => {
  const baseUrl = getRequestBaseUrl(request);
  const pages = ["/", "/privacy.html", "/terms.html", "/blogs.html"];
  const urls = pages
    .map((page) => `  <url><loc>${baseUrl}${page}</loc></url>`)
    .join("\n");

  response.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`);
});

app.get("/robots.txt", (request, response) => {
  const baseUrl = getRequestBaseUrl(request);

  response.type("text/plain").send([
    "User-agent: *",
    "Allow: /",
    `Sitemap: ${baseUrl}/sitemap.xml`,
    "",
  ].join("\n"));
});

app.use(
  express.static(publicDir, {
    extensions: ["html"],
    maxAge: appConfig.isProduction ? "1h" : 0,
  }),
);

app.get("/api/health", (request, response) => {
  response.json({
    ok: true,
    status: "ok",
    service: "sentinel-scan",
    version: "3.1.0",
    storageMode: appConfig.storageMode,
    auth: {
      googleEnabled: Boolean(appConfig.googleClientId),
    },
    timestamp: new Date().toISOString(),
  });
});

app.use("/api/auth", authRateLimiter, authRoutes);
app.use("/api/scans", scanRoutes);
app.use("/api/reports", reportRoutes);

app.get(/^(?!\/api).*/, (request, response) => {
  response.sendFile(path.join(publicDir, "index.html"));
});

app.use(notFoundHandler);
app.use(errorHandler);

export default app;


