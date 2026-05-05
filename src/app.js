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

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },

    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],

        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://accounts.google.com",
          "https://apis.google.com",
        ],

        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
        ],

        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
          "data:",
        ],

        imgSrc: [
          "'self'",
          "data:",
          "https:",
        ],

        connectSrc: [
          "'self'",
          "https://accounts.google.com",
          "https://*.googleapis.com",
        ],

        frameSrc: [
          "'self'",
          "https://accounts.google.com",
        ],

        objectSrc: ["'none'"],

        upgradeInsecureRequests: [],
      },
    },
  }),
);

app.use(
  cors({
    origin: appConfig.corsOrigin === "*" ? true : appConfig.corsOrigin,
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

app.use(
  express.static(publicDir, {
    extensions: ["html"],
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