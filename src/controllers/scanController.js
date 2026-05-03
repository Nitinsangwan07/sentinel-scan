import { buildAiAssist } from "../services/aiAssistService.js";
import {
  executeScan,
  getUserScanById,
  listUserScans,
} from "../services/scanService.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { createError } from "../utils/createError.js";

function normalizeTarget(target) {
  const trimmed = String(target || "").trim();
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withProtocol);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw createError(400, "Only HTTP and HTTPS targets are supported.");
  }

  return parsed.toString();
}

export const createScan = asyncHandler(async (request, response) => {
  const scan = await executeScan({
    userId: request.user.id,
    url: normalizeTarget(request.body.url),
    options: request.body.options || {},
  });

  response.status(201).json(scan);
});

export const listScans = asyncHandler(async (request, response) => {
  response.json(await listUserScans(request.user.id));
});

export const getScan = asyncHandler(async (request, response) => {
  const scan = await getUserScanById(request.params.scanId, request.user.id);

  if (!scan) {
    throw createError(404, "Scan not found.");
  }

  response.json(scan);
});

export const getAiAssist = asyncHandler(async (request, response) => {
  const scan = await getUserScanById(request.params.scanId, request.user.id);

  if (!scan) {
    throw createError(404, "Scan not found.");
  }

  response.json({
    aiAssist: scan.aiAssist || (await buildAiAssist(scan)),
  });
});
