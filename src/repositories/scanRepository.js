import mongoose from "mongoose";

import { appConfig } from "../config/env.js";
import { ScanModel } from "../models/Scan.js";
import {
  createFallbackId,
  getFallbackCollection,
  setFallbackCollection,
} from "../services/fallbackStoreService.js";

function normalizeScan(scan) {
  if (!scan) {
    return null;
  }

  const base = typeof scan.toObject === "function" ? scan.toObject() : scan;

  return {
    ...base,
    id: String(base._id || base.id),
    userId: String(base.userId),
  };
}

export const scanRepository = {
  async create(scan) {
    if (appConfig.storageMode === "mongo") {
      return normalizeScan(await ScanModel.create(scan));
    }

    const scans = await getFallbackCollection("scans");
    const nextScan = {
      ...scan,
      id: createFallbackId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await setFallbackCollection("scans", [nextScan, ...scans]);
    return normalizeScan(nextScan);
  },

  async listByUser(userId) {
    if (appConfig.storageMode === "mongo") {
      const scans = await ScanModel.find({ userId }).sort({ scannedAt: -1 }).lean();
      return scans.map(normalizeScan);
    }

    const scans = await getFallbackCollection("scans");
    return scans
      .filter((scan) => scan.userId === userId)
      .sort((left, right) => new Date(right.scannedAt) - new Date(left.scannedAt))
      .map(normalizeScan);
  },

  async findByIdForUser(id, userId) {
    if (appConfig.storageMode === "mongo") {
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return null;
      }

      return normalizeScan(await ScanModel.findOne({ _id: id, userId }).lean());
    }

    const scans = await getFallbackCollection("scans");
    return normalizeScan(scans.find((scan) => scan.id === id && scan.userId === userId));
  },
};