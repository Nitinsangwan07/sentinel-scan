import PDFDocument from "pdfkit";

import { reportRepository } from "../repositories/reportRepository.js";
import { createError } from "../utils/createError.js";

const SUPPORTED_EXPORTS = new Set(["pdf", "txt", "md", "json"]);

function buildTextReport(scan) {
  const lines = [
    "Sentinel Scan Report",
    "====================",
    "",
    `Target URL: ${scan.target}`,
    `Final URL: ${scan.finalUrl}`,
    `Risk Score: ${scan.risk.score}/100 (${scan.risk.band})`,
    `Scan Timestamp: ${scan.scannedAt}`,
    `Scan Duration: ${scan.durationMs} ms`,
    "",
    "Severity Breakdown",
    "------------------",
  ];

  for (const [severity, count] of Object.entries(scan.summary.bySeverity || {})) {
    lines.push(`- ${severity}: ${count}`);
  }

  lines.push("", "Executive Summary", "-----------------", scan.report.executiveSummary, "");
  lines.push("Recommendations", "---------------");

  for (const action of scan.report.priorityActions || []) {
    lines.push(`${action.priority}. ${action.action} (${action.reason})`);
  }

  lines.push("", "Findings Table", "--------------");

  for (const finding of scan.findings || []) {
    lines.push(`- [${finding.severity}] ${finding.title} | ${finding.category} | ${finding.location || "Global"}`);
  }

  return lines.join("\n");
}

function buildMarkdownReport(scan) {
  return scan.markdown || buildTextReport(scan);
}

function buildJsonReport(scan) {
  return JSON.stringify(
    {
      metadata: {
        target: scan.target,
        finalUrl: scan.finalUrl,
        scannedAt: scan.scannedAt,
        durationMs: scan.durationMs,
      },
      risk: scan.risk,
      summary: scan.summary,
      report: scan.report,
      findings: scan.findings,
    },
    null,
    2,
  );
}

async function buildPdfBuffer(scan) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      margin: 42,
      size: "A4",
      info: {
        Title: "Sentinel Scan Report",
        Author: "Sentinel Scan",
      },
    });
    const chunks = [];

    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.rect(0, 0, doc.page.width, 120).fill("#09131f");
    doc
      .fillColor("#7dd3fc")
      .fontSize(13)
      .text("Sentinel Scan", 42, 34)
      .fillColor("#ffffff")
      .fontSize(26)
      .text("Passive Security Assessment Report", 42, 54);

    doc.moveDown(5);
    doc.fillColor("#111827").fontSize(11);

    const metadata = [
      ["Target", scan.target],
      ["Final URL", scan.finalUrl],
      ["Scanned At", scan.scannedAt],
      ["Risk Score", `${scan.risk.score}/100 (${scan.risk.band})`],
      ["Duration", `${scan.durationMs} ms`],
    ];

    metadata.forEach(([label, value]) => {
      doc.font("Helvetica-Bold").text(`${label}: `, { continued: true }).font("Helvetica").text(String(value));
    });

    doc.moveDown(1.2);
    doc.font("Helvetica-Bold").fontSize(16).text("Executive Summary");
    doc.moveDown(0.4);
    doc.font("Helvetica").fontSize(11).fillColor("#374151").text(scan.report.executiveSummary);

    doc.moveDown(1);
    doc.fillColor("#111827").font("Helvetica-Bold").fontSize(16).text("Severity Breakdown");
    doc.moveDown(0.4);

    Object.entries(scan.summary.bySeverity || {}).forEach(([severity, count]) => {
      doc.font("Helvetica").fontSize(11).text(`${severity}: ${count}`);
    });

    doc.moveDown(1);
    doc.font("Helvetica-Bold").fontSize(16).text("Recommendations");
    doc.moveDown(0.4);
    (scan.report.priorityActions || []).forEach((action) => {
      doc.font("Helvetica").fontSize(11).text(`${action.priority}. ${action.action}`);
    });

    doc.moveDown(1);
    doc.font("Helvetica-Bold").fontSize(16).text("Findings Table");
    doc.moveDown(0.4);

    (scan.findings || []).slice(0, 18).forEach((finding, index) => {
      const fillColor = finding.severity === "critical" ? "#7f1d1d" : finding.severity === "high" ? "#9a3412" : "#0f172a";
      doc
        .roundedRect(42, doc.y, 510, 48, 8)
        .fillAndStroke("#f8fafc", "#d1d5db")
        .fillColor(fillColor)
        .font("Helvetica-Bold")
        .fontSize(11)
        .text(`${index + 1}. ${finding.title}`, 54, doc.y - 40, { width: 360 })
        .font("Helvetica")
        .fillColor("#475569")
        .fontSize(9)
        .text(`${finding.severity.toUpperCase()} | ${finding.category} | ${finding.location || "Global"}`, 54, doc.y - 24, { width: 360 });
      doc.moveDown(2.7);
    });

    doc.end();
  });
}

export async function exportReport({ scan, userId, format }) {
  if (!SUPPORTED_EXPORTS.has(format)) {
    throw createError(400, `Unsupported export format: ${format}`);
  }

  const safeHost = new URL(scan.finalUrl || scan.target).hostname.replace(/[^\w.-]+/g, "_");
  const fileName = `sentinel-scan-${safeHost}.${format === "md" ? "md" : format}`;

  if (format === "pdf") {
    const buffer = await buildPdfBuffer(scan);
    await reportRepository.create({
      userId,
      scanId: scan.id,
      format,
      fileName,
      sizeBytes: buffer.length,
      content: buffer.toString("base64"),
    });

    return {
      contentType: "application/pdf",
      fileName,
      payload: buffer,
    };
  }

  const content =
    format === "txt"
      ? buildTextReport(scan)
      : format === "md"
        ? buildMarkdownReport(scan)
        : buildJsonReport(scan);

  await reportRepository.create({
    userId,
    scanId: scan.id,
    format,
    fileName,
    sizeBytes: Buffer.byteLength(content),
    content,
  });

  return {
    contentType:
      format === "txt"
        ? "text/plain; charset=utf-8"
        : format === "md"
          ? "text/markdown; charset=utf-8"
          : "application/json; charset=utf-8",
    fileName,
    payload: content,
  };
}
