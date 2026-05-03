import mongoose from "mongoose";

const reportSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    scanId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Scan",
      required: true,
      index: true,
    },
    format: {
      type: String,
      required: true,
      enum: ["pdf", "txt", "md", "json"],
      index: true,
    },
    fileName: { type: String, required: true },
    sizeBytes: { type: Number, required: true },
    content: { type: String, required: true },
  },
  {
    timestamps: true,
  },
);

reportSchema.index({ userId: 1, scanId: 1, createdAt: -1 });

export const ReportModel = mongoose.models.Report || mongoose.model("Report", reportSchema);
