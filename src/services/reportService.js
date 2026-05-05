import PDFDocument from "pdfkit";

import { reportRepository } from "../repositories/reportRepository.js";
import { createError } from "../utils/createError.js";

const SUPPORTED_EXPORTS = new Set(["pdf", "txt", "md", "json"]);
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS = {
  critical: "#c7544f",
  high: "#d07a3a",
  medium: "#bc9544",
  low: "#348f6a",
  info: "#53789b",
};

function toRecommendations(scan) {
  return (scan.report.priorityActions || []).slice(0, 6).map((action, index) => `${index + 1}. ${action.action} (${action.reason})`);
}

function buildTextReport(scan) {
  const lines = [
    "SENTINEL SCAN REPORT",
    "====================",
    "",
    `Target URL: ${scan.target}`,
    `Final URL: ${scan.finalUrl}`,
    `Scan Timestamp: ${scan.scannedAt}`,
    `Scan Duration: ${scan.durationMs} ms`,
    `Risk Score: ${scan.risk.score}/100 (${scan.risk.band})`,
    `Pages Crawled: ${scan.coverage.pagesCrawled}`,
    `Top Category: ${Object.entries(scan.summary.byCategory || {}).sort((a, b) => b[1] - a[1])[0]?.[0] || "n/a"}`,
    "",
    "EXECUTIVE SUMMARY",
    "-----------------",
    scan.report.executiveSummary,
    "",
    "SEVERITY BREAKDOWN",
    "------------------",
  ];

  for (const severity of SEVERITY_ORDER) {
    if (scan.summary.bySeverity?.[severity]) {
      lines.push(`- ${severity}: ${scan.summary.bySeverity[severity]}`);
    }
  }

  lines.push("", "PRIORITY RECOMMENDATIONS", "------------------------", ...toRecommendations(scan), "", "FINDINGS", "--------");

  for (const finding of scan.findings) {
    lines.push(`[${finding.severity.toUpperCase()} | confidence ${finding.confidence || "--"}%] ${finding.title}`);
    lines.push(`Category: ${finding.category}`);
    lines.push(`Affected: ${finding.location || "Global"}`);
    lines.push(`Evidence: ${finding.evidence}`);
    lines.push(`Remediation: ${finding.remediation}`);
    lines.push("");
  }

  return lines.join("\n");
}

function buildMarkdownReport(scan) {
  const lines = [
    "# Sentinel Scan Report",
    "",
    "## Metadata",
    "",
    `- Target: ${scan.target}`,
    `- Final URL: ${scan.finalUrl}`,
    `- Scanned at: ${scan.scannedAt}`,
    `- Duration: ${scan.durationMs} ms`,
    `- Risk score: ${scan.risk.score}/100 (${scan.risk.band})`,
    `- Pages crawled: ${scan.coverage.pagesCrawled}`,
    "",
    "## Executive Summary",
    "",
    scan.report.executiveSummary,
    "",
    "## Severity Breakdown",
    "",
  ];

  for (const severity of SEVERITY_ORDER) {
    if (scan.summary.bySeverity?.[severity]) {
      lines.push(`- ${severity}: ${scan.summary.bySeverity[severity]}`);
    }
  }

  lines.push("", "## Recommendations", "", ...toRecommendations(scan), "", "## Findings", "");

  for (const finding of scan.findings) {
    lines.push(`### ${finding.title}`);
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Confidence: ${finding.confidence || "--"}% (${finding.confidenceLabel || "n/a"})`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- Affected URL: ${finding.location || "Global"}`);
    lines.push(`- Evidence: ${finding.evidence}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Remediation: ${finding.remediation}`);
    lines.push("");
  }

  return lines.join("\n");
}

function buildJsonReport(scan) {
  return JSON.stringify(
    {
      metadata: {
        product: scan.product,
        version: scan.version,
        target: scan.target,
        finalUrl: scan.finalUrl,
        scannedAt: scan.scannedAt,
        durationMs: scan.durationMs,
        pagesCrawled: scan.coverage.pagesCrawled,
      },
      risk: scan.risk,
      summary: scan.summary,
      report: scan.report,
      findings: scan.findings,
      inventory: scan.inventory,
      scope: scan.scope,
    },
    null,
    2,
  );
}

function drawPageFooter(doc, pageNumber) {
  const page = doc.page;
  doc.save();
  doc.fontSize(8).fillColor("#8a7f73").text(`Page ${pageNumber}`, 42, page.height - 28, {
    align: "right",
    width: page.width - 84,
  });
  doc.restore();
}

function drawSeverityBars(doc, bySeverity, yStart) {
  let y = yStart;
  const total = Object.values(bySeverity || {}).reduce((sum, count) => sum + count, 0) || 1;

  for (const severity of SEVERITY_ORDER) {
    if (!bySeverity?.[severity]) continue;
    const count = bySeverity[severity];
    const width = Math.max(30, Math.round((count / total) * 230));
    doc.fillColor("#3d352d").fontSize(10).text(severity.toUpperCase(), 42, y + 4, { width: 90 });
    doc.roundedRect(138, y, width, 12, 6).fill(SEVERITY_COLORS[severity]);
    doc.fillColor("#3d352d").text(String(count), 380, y + 1);
    y += 22;
  }

  return y;
}

async function buildPdfBuffer(scan) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 42, size: "A4", bufferPages: true });
    const chunks = [];

    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.rect(0, 0, doc.page.width, 112).fill("#286f67");
    doc.fillColor("#f8f6f1").font("Helvetica-Bold").fontSize(13).text("Sentinel Scan", 42, 28);
    doc.fontSize(24).text("Passive Web Security Assessment", 42, 48);
    doc.font("Helvetica").fontSize(10).text("Professional passive findings for authorized targets only", 42, 78);

    doc.y = 132;
    doc.fillColor("#241f19").font("Helvetica-Bold").fontSize(16).text("Executive Summary");
    doc.moveDown(0.5);
    doc.font("Helvetica").fontSize(10.5).fillColor("#5f564b").text(scan.report.executiveSummary, { width: 510, lineGap: 2 });
    doc.moveDown(1.2);

    doc.fillColor("#241f19").font("Helvetica-Bold").fontSize(16).text("Scan Metadata");
    doc.moveDown(0.5);
    [
      ["Target", scan.target],
      ["Final URL", scan.finalUrl],
      ["Scanned At", scan.scannedAt],
      ["Duration", `${scan.durationMs} ms`],
      ["Risk Score", `${scan.risk.score}/100 (${scan.risk.band})`],
      ["Pages Crawled", String(scan.coverage.pagesCrawled)],
    ].forEach(([label, value]) => {
      doc.font("Helvetica-Bold").fillColor("#241f19").text(`${label}: `, { continued: true }).font("Helvetica").fillColor("#5f564b").text(String(value));
    });

    doc.moveDown(1.2);
    doc.font("Helvetica-Bold").fillColor("#241f19").fontSize(16).text("Severity Breakdown");
    const nextY = drawSeverityBars(doc, scan.summary.bySeverity || {}, doc.y + 8);
    doc.y = nextY + 10;

    doc.font("Helvetica-Bold").fillColor("#241f19").fontSize(16).text("Priority Recommendations");
    doc.moveDown(0.5);
    toRecommendations(scan).forEach((line) => {
      doc.font("Helvetica").fontSize(10.5).fillColor("#5f564b").text(line, { width: 510, lineGap: 2 });
    });

    doc.addPage();
    doc.fillColor("#241f19").font("Helvetica-Bold").fontSize(16).text("Findings Overview");
    doc.moveDown(0.5);

    scan.findings.slice(0, 16).forEach((finding, index) => {
      if (doc.y > 730) {
        doc.addPage();
      }

      doc.roundedRect(42, doc.y, 510, 60, 12).fillAndStroke("#fffdf8", "#dfd7cb");
      const startY = doc.y - 54;
      doc.fillColor(SEVERITY_COLORS[finding.severity] || "#53789b").font("Helvetica-Bold").fontSize(10).text(`${index + 1}. ${finding.title}`, 56, startY, { width: 330 });
      doc.fillColor("#5f564b").font("Helvetica").fontSize(9).text(`${finding.severity.toUpperCase()} | ${finding.category} | confidence ${finding.confidence || "--"}%`, 56, startY + 18);
      doc.text(`Affected: ${finding.location || "Global"}`, 56, startY + 31, { width: 210 });
      doc.text(`Evidence: ${finding.evidence}`, 270, startY, { width: 265, height: 46 });
      doc.y += 70;
    });

    const range = doc.bufferedPageRange();
    for (let index = range.start; index < range.start + range.count; index += 1) {
      doc.switchToPage(index);
      drawPageFooter(doc, index - range.start + 1);
    }

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
    return { contentType: "application/pdf", fileName, payload: buffer };
  }

  const content = format === "txt" ? buildTextReport(scan) : format === "md" ? buildMarkdownReport(scan) : buildJsonReport(scan);

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
