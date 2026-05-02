import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.resolve(__dirname, "../../data");
const scansFile = path.join(dataDir, "scans.json");
const MAX_SCANS = 30;

async function ensureStore() {
  await fs.mkdir(dataDir, { recursive: true });

  try {
    await fs.access(scansFile);
  } catch {
    await fs.writeFile(scansFile, "[]", "utf8");
  }
}

async function readScans() {
  await ensureStore();

  try {
    const contents = await fs.readFile(scansFile, "utf8");
    const parsed = JSON.parse(contents);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeScans(scans) {
  await ensureStore();
  await fs.writeFile(scansFile, JSON.stringify(scans, null, 2), "utf8");
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
    coverage: {
      pagesCrawled: scan.coverage?.pagesCrawled || scan.coverage?.pages?.length || 0,
    },
  };
}

export async function listScanSummaries() {
  const scans = await readScans();
  return scans.map(toSummary);
}

export async function getScanById(id) {
  const scans = await readScans();
  return scans.find((scan) => scan.id === id) || null;
}

export async function saveScan(scan) {
  const scans = await readScans();
  const nextScans = [scan, ...scans.filter((existing) => existing.id !== scan.id)].slice(0, MAX_SCANS);
  await writeScans(nextScans);
  return scan;
}
