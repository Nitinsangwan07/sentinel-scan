import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.resolve(__dirname, "../../data");
const scansFile = path.join(dataDir, "scans.json");
const MAX_SCANS = 30;
const DUPLICATE_WINDOW_MS = 15 * 60 * 1000;

// A small in-memory cache keeps history reads fast without changing the JSON-backed storage model.
let scansCache = null;

function createEmptyStore() {
  return {
    updatedAt: new Date().toISOString(),
    scans: [],
  };
}

async function ensureStore() {
  await fs.mkdir(dataDir, { recursive: true });

  try {
    await fs.access(scansFile);
  } catch {
    await fs.writeFile(scansFile, JSON.stringify(createEmptyStore(), null, 2), "utf8");
  }
}

function normalizeStorePayload(payload) {
  if (Array.isArray(payload)) {
    return {
      updatedAt: new Date().toISOString(),
      scans: payload,
    };
  }

  if (payload && Array.isArray(payload.scans)) {
    return {
      updatedAt: payload.updatedAt || new Date().toISOString(),
      scans: payload.scans,
    };
  }

  return createEmptyStore();
}

async function readStore() {
  if (scansCache) {
    return scansCache;
  }

  await ensureStore();

  try {
    const contents = await fs.readFile(scansFile, "utf8");
    scansCache = normalizeStorePayload(JSON.parse(contents));
  } catch {
    scansCache = createEmptyStore();
  }

  return scansCache;
}

async function writeStore(store) {
  scansCache = {
    updatedAt: new Date().toISOString(),
    scans: store.scans,
  };
  await ensureStore();
  await fs.writeFile(scansFile, JSON.stringify(scansCache, null, 2), "utf8");
}

function toSummary(scan) {
  return {
    id: scan.id,
    target: scan.target,
    finalUrl: scan.finalUrl,
    scannedAt: scan.scannedAt,
    risk: scan.risk,
    summary: scan.summary,
    options: scan.options,
    durationMs: scan.durationMs || 0,
    coverage: {
      pagesCrawled: scan.coverage?.pagesCrawled || scan.coverage?.pages?.length || 0,
    },
  };
}

function createScanFingerprint(scan) {
  const source = JSON.stringify({
    target: scan.target,
    finalUrl: scan.finalUrl,
    options: scan.options,
    risk: scan.risk,
    total: scan.summary?.total || 0,
    severities: scan.summary?.bySeverity || {},
    findings: (scan.findings || []).map((finding) => ({
      title: finding.title,
      severity: finding.severity,
      location: finding.location || null,
    })),
  });

  return crypto.createHash("sha1").update(source).digest("hex");
}

function findDuplicateScan(scans, fingerprint, scannedAt) {
  const scanTime = new Date(scannedAt).getTime();

  return scans.find((scan) => {
    if (scan.fingerprint !== fingerprint) {
      return false;
    }

    const existingTime = new Date(scan.scannedAt).getTime();
    return Math.abs(scanTime - existingTime) <= DUPLICATE_WINDOW_MS;
  });
}

export async function listScanSummaries() {
  const store = await readStore();
  return store.scans.map(toSummary);
}

export async function getScanById(id) {
  const store = await readStore();
  return store.scans.find((scan) => scan.id === id) || null;
}

export async function saveScan(scan) {
  const store = await readStore();
  const fingerprint = createScanFingerprint(scan);
  const duplicate = findDuplicateScan(store.scans, fingerprint, scan.scannedAt);

  if (duplicate) {
    return duplicate;
  }

  const nextScan = {
    ...scan,
    fingerprint,
    storedAt: new Date().toISOString(),
  };

  const nextScans = [nextScan, ...store.scans.filter((existing) => existing.id !== nextScan.id)].slice(0, MAX_SCANS);
  await writeStore({ scans: nextScans });
  return nextScan;
}
