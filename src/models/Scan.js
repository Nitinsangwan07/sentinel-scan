import mongoose from "mongoose";

const findingSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    title: { type: String, required: true },
    severity: { type: String, required: true, index: true },
    score: { type: Number, default: 0 },
    category: { type: String, required: true, index: true },
    description: { type: String, required: true },
    impact: { type: String, required: true },
    remediation: { type: String, required: true },
    evidence: { type: String, required: true },
    location: { type: String, default: null },
    confidence: { type: Number, default: 70 },
    confidenceLabel: { type: String, default: "medium" },
    affectedUrls: { type: [String], default: [] },
  },
  { _id: false },
);

const scanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    target: { type: String, required: true, index: true },
    finalUrl: { type: String, required: true },
    scannedAt: { type: Date, required: true, index: true },
    durationMs: { type: Number, required: true },
    options: {
      includeSubpages: Boolean,
      maxPages: Number,
      requestTimeoutMs: Number,
    },
    risk: {
      score: Number,
      band: String,
    },
    summary: {
      total: Number,
      bySeverity: { type: mongoose.Schema.Types.Mixed, default: {} },
      byCategory: { type: mongoose.Schema.Types.Mixed, default: {} },
    },
    findings: {
      type: [findingSchema],
      default: [],
    },
    coverage: { type: mongoose.Schema.Types.Mixed, default: {} },
    inventory: { type: mongoose.Schema.Types.Mixed, default: {} },
    transport: { type: mongoose.Schema.Types.Mixed, default: {} },
    auxiliaryFiles: { type: [mongoose.Schema.Types.Mixed], default: [] },
    sensitiveFiles: { type: [mongoose.Schema.Types.Mixed], default: [] },
    report: { type: mongoose.Schema.Types.Mixed, default: {} },
    markdown: { type: String, default: "" },
    aiAssist: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  {
    timestamps: true,
  },
);

scanSchema.index({ userId: 1, scannedAt: -1 });

export const ScanModel = mongoose.models.Scan || mongoose.model("Scan", scanSchema);
