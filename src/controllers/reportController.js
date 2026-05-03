import { getUserScanById } from "../services/scanService.js";
import { exportReport } from "../services/reportService.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { createError } from "../utils/createError.js";

export const downloadReport = asyncHandler(async (request, response) => {
  const scan = await getUserScanById(request.params.scanId, request.user.id);

  if (!scan) {
    throw createError(404, "Scan not found.");
  }

  const report = await exportReport({
    scan,
    userId: request.user.id,
    format: request.params.format,
  });

  response.setHeader("Content-Type", report.contentType);
  response.setHeader("Content-Disposition", `attachment; filename="${report.fileName}"`);
  response.send(report.payload);
});
