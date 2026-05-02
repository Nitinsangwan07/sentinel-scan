import crypto from "node:crypto";
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { getScanById, listScanSummaries, saveScan } from "./lib/storage.js";
import { normalizeScanOptions, scanWebsite } from "./lib/scanner.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, "../public");
const port = Number(process.env.PORT || 3000);

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload, null, 2));
}

async function readRequestBody(request) {
  const chunks = [];

  for await (const chunk of request) {
    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString("utf8");
}

function normalizeTarget(target) {
  if (!target || typeof target !== "string") {
    throw new Error("A target URL is required.");
  }

  const trimmed = target.trim();
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withProtocol);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS targets are supported.");
  }

  return parsed.toString();
}

async function serveStaticAsset(requestPath, response) {
  const safePath = requestPath === "/" ? "/index.html" : requestPath;
  const resolvedPath = path.resolve(publicDir, `.${safePath}`);

  if (!resolvedPath.startsWith(publicDir)) {
    sendJson(response, 403, { error: "Forbidden" });
    return;
  }

  try {
    const data = await fs.readFile(resolvedPath);
    const extension = path.extname(resolvedPath);

    response.writeHead(200, {
      "Content-Type": contentTypes[extension] || "application/octet-stream",
      "Cache-Control": extension === ".html" ? "no-store" : "public, max-age=3600",
    });
    response.end(data);
  } catch (error) {
    if (safePath !== "/index.html") {
      sendJson(response, 404, { error: "Not found" });
      return;
    }

    response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Application entrypoint missing.");
  }
}

function extractScanId(pathname) {
  const match = pathname.match(/^\/api\/scans\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);

  if (request.method === "GET" && requestUrl.pathname === "/api/health") {
    sendJson(response, 200, {
      status: "ok",
      service: "sentinel-scan",
      timestamp: new Date().toISOString(),
    });
    return;
  }

  if (request.method === "GET" && requestUrl.pathname === "/api/scans") {
    const scans = await listScanSummaries();
    sendJson(response, 200, { scans });
    return;
  }

  if (request.method === "GET" && extractScanId(requestUrl.pathname)) {
    const scanId = extractScanId(requestUrl.pathname);
    const scan = await getScanById(scanId);

    if (!scan) {
      sendJson(response, 404, { error: "Scan not found." });
      return;
    }

    sendJson(response, 200, scan);
    return;
  }

  if (request.method === "POST" && requestUrl.pathname === "/api/scan") {
    try {
      const body = await readRequestBody(request);
      const payload = body ? JSON.parse(body) : {};
      const target = normalizeTarget(payload.url);
      const options = normalizeScanOptions(payload.options);
      const startedAt = Date.now();
      const result = await scanWebsite(target, options);
      const scanRecord = {
        id: crypto.randomUUID(),
        ...result,
        durationMs: Date.now() - startedAt,
      };
      const persistedScan = await saveScan(scanRecord);

      sendJson(response, 200, persistedScan);
    } catch (error) {
      const statusCode = error instanceof SyntaxError ? 400 : 422;

      sendJson(response, statusCode, {
        error: error.message || "Unable to process the scan request.",
      });
    }
    return;
  }

  if (request.method === "GET") {
    await serveStaticAsset(requestUrl.pathname, response);
    return;
  }

  sendJson(response, 405, { error: "Method not allowed" });
});

server.listen(port, () => {
  console.log(`Sentinel Scan running on http://localhost:${port}`);
});
