import { appConfig } from "../config/env.js";
import { ReportModel } from "../models/Report.js";
import {
  createFallbackId,
  getFallbackCollection,
  setFallbackCollection,
} from "../services/fallbackStoreService.js";

function normalizeReport(report) {
  if (!report) {
    return null;
  }

  const base = typeof report.toObject === "function" ? report.toObject() : report;

  return {
    ...base,
    id: String(base._id || base.id),
    userId: String(base.userId),
    scanId: String(base.scanId),
  };
}

export const reportRepository = {
  async create(report) {
    if (appConfig.storageMode === "mongo") {
      return normalizeReport(await ReportModel.create(report));
    }

    const reports = await getFallbackCollection("reports");
    const nextReport = {
      ...report,
      id: createFallbackId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await setFallbackCollection("reports", [nextReport, ...reports]);
    return normalizeReport(nextReport);
  },
};
