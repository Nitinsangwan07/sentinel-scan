import crypto from "node:crypto";

import { assertSafeUrl, normalizeScanOptions, scanWebsite } from "../lib/scanner.js";
import { scanRepository } from "../repositories/scanRepository.js";
import { createError } from "../utils/createError.js";
import { buildAiAssist } from "./aiAssistService.js";

const MAX_URL_LENGTH = 2048;

function buildTrend(scans) {
  return scans
    .slice(0, 10)
    .map((scan) => ({
      scannedAt: scan.scannedAt,
      riskScore: scan.risk?.score || 0,
      findings: scan.summary?.total || 0,
    }))
    .reverse();
}

function toScanSummary(scan) {
  return {
    id: scan.id,
    target: scan.target,
    finalUrl: scan.finalUrl,
    scannedAt: scan.scannedAt,
    durationMs: scan.durationMs,
    risk: scan.risk,
    summary: scan.summary,
    coverage: {
      pagesCrawled: scan.coverage?.pagesCrawled || scan.coverage?.pages?.length || 0,
    },
  };
}

export async function executeScan({ userId, url, options }) {
  if (!url || typeof url !== "string") {
    throw createError(400, "A target URL is required.");
  }

  if (url.length > MAX_URL_LENGTH) {
    throw createError(400, "The target URL is too long.");
  }

  await assertSafeUrl(url);

  const startedAt = Date.now();
  const normalizedOptions = normalizeScanOptions(options);
  const result = await scanWebsite(url, normalizedOptions);
  const aiAssist = await buildAiAssist(result);

  const scanRecord = await scanRepository.create({
    id: crypto.randomUUID(),
    userId,
    ...result,
    aiAssist,
    durationMs: Date.now() - startedAt,
  });

  return scanRecord;
}

export async function listUserScans(userId) {
  const scans = await scanRepository.listByUser(userId);

  return {
    scans: scans.map(toScanSummary),
    metrics: {
      totalScans: scans.length,
      averageRisk:
        scans.length > 0
          ? Math.round(scans.reduce((sum, scan) => sum + (scan.risk?.score || 0), 0) / scans.length)
          : 0,
      riskTrend: buildTrend(scans),
    },
  };
}

export async function getUserScanById(scanId, userId) {
  return scanRepository.findByIdForUser(scanId, userId);
}