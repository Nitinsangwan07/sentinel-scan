import PDFDocument from "pdfkit";

import { reportRepository } from "../repositories/reportRepository.js";
import { createError } from "../utils/createError.js";

const SUPPORTED_EXPORTS = new Set(["pdf", "txt", "md", "json"]);
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS = {
  critical: "#c7544f",
  high: "#d07a3a",
  medium: "#a78a35",
  low: "#348f6a",
  info: "#53789b",
};
const PAGE_MARGIN = 44;
const CONTENT_WIDTH = 507;
const FOOTER_Y = 790;

function safeText(value, fallback = "n/a") {
  return String(value ?? fallback);
}

function formatDuration(durationMs) {
  const duration = Number(durationMs);
  if (!Number.isFinite(duration) || duration <= 0) return "n/a";
  return duration < 1000 ? `${duration} ms` : `${(duration / 1000).toFixed(1)} s`;
}

function toRecommendations(scan) {
  return (scan.report?.priorityActions || [])
    .slice(0, 6)
    .map((action, index) => `${index + 1}. ${action.action} (${action.reason})`);
}

function buildTextReport(scan) {
  const lines = [
    "SENTINEL SCAN REPORT",
    "====================",
    "",
    `Target URL: ${scan.target}`,
    `Final URL: ${scan.finalUrl}`,
    `Scan Timestamp: ${scan.scannedAt}`,
    `Scan Duration: ${formatDuration(scan.durationMs)}`,
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
    `- Duration: ${formatDuration(scan.durationMs)}`,
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

function ensureSpace(doc, height) {
  if (doc.y + height > FOOTER_Y) {
    doc.addPage();
    doc.y = PAGE_MARGIN;
  }
}

function drawSectionTitle(doc, title) {
  ensureSpace(doc, 34);
  doc.font("Helvetica-Bold").fontSize(14).fillColor("#242521").text(title, PAGE_MARGIN, doc.y);
  doc.moveDown(0.45);
}

function drawPageFooter(doc, pageNumber, totalPages) {
  doc.save();
  doc.font("Helvetica").fontSize(8).fillColor("#8a8f86").text(
    `Sentinel Scan Security Report  |  Page ${pageNumber} of ${totalPages}`,
    PAGE_MARGIN,
    doc.page.height - 30,
    { align: "center", width: CONTENT_WIDTH },
  );
  doc.restore();
}

function drawHeader(doc, scan) {
  doc.rect(0, 0, doc.page.width, 118).fill("#286f67");
  doc.circle(66, 46, 20).fill("#f8f6f1");
  doc.circle(66, 46, 11).fill("#286f67");
  doc.fillColor("#f8f6f1").font("Helvetica-Bold").fontSize(13).text("Sentinel Scan", 96, 30);
  doc.fontSize(24).text("Passive Web Security Report", 96, 50, { width: 390 });
  doc.font("Helvetica").fontSize(10).text("Authorized, passive website assessment", 96, 82);

  doc.roundedRect(408, 30, 128, 58, 10).fill("#f8f6f1");
  doc.fillColor("#286f67").font("Helvetica-Bold").fontSize(20).text(`${scan.risk?.score ?? 0}/100`, 424, 42);
  doc.fillColor("#5f665d").font("Helvetica").fontSize(9).text(safeText(scan.risk?.band, "Unknown"), 424, 66);
  doc.y = 142;
}

function drawMetadata(doc, scan) {
  drawSectionTitle(doc, "Scan Metadata");
  const rows = [
    ["Target", scan.target],
    ["Final URL", scan.finalUrl],
    ["Scanned", scan.scannedAt],
    ["Duration", formatDuration(scan.durationMs)],
    ["Pages Crawled", scan.coverage?.pagesCrawled],
    ["Total Findings", scan.summary?.total],
  ];

  const startY = doc.y;
  rows.forEach(([label, value], index) => {
    const x = index % 2 === 0 ? PAGE_MARGIN : 302;
    const y = startY + Math.floor(index / 2) * 34;
    doc.font("Helvetica-Bold").fontSize(8).fillColor("#6f736c").text(label.toUpperCase(), x, y);
    doc.font("Helvetica").fontSize(9.5).fillColor("#242521").text(safeText(value), x, y + 12, { width: 218, ellipsis: true });
  });
  doc.y = startY + 112;
}

function drawSeverityBars(doc, bySeverity = {}) {
  drawSectionTitle(doc, "Severity Breakdown");
  const total = Object.values(bySeverity).reduce((sum, count) => sum + count, 0) || 1;

  for (const severity of SEVERITY_ORDER) {
    const count = bySeverity[severity] || 0;
    ensureSpace(doc, 24);
    const y = doc.y;
    const barWidth = Math.max(count ? 24 : 0, Math.round((count / total) * 260));
    doc.font("Helvetica-Bold").fontSize(9).fillColor("#3f4540").text(severity.toUpperCase(), PAGE_MARGIN, y + 2, { width: 82 });
    doc.roundedRect(PAGE_MARGIN + 94, y, 270, 12, 6).fill("#edf0eb");
    if (barWidth > 0) {
      doc.roundedRect(PAGE_MARGIN + 94, y, barWidth, 12, 6).fill(SEVERITY_COLORS[severity]);
    }
    doc.font("Helvetica").fontSize(9).fillColor("#3f4540").text(String(count), PAGE_MARGIN + 380, y + 1);
    doc.y += 23;
  }
  doc.moveDown(0.4);
}

function drawRecommendations(doc, scan) {
  const recommendations = toRecommendations(scan);
  if (!recommendations.length) return;

  drawSectionTitle(doc, "Priority Recommendations");
  recommendations.forEach((line) => {
    ensureSpace(doc, 32);
    doc.font("Helvetica").fontSize(10).fillColor("#4f574f").text(line, PAGE_MARGIN, doc.y, {
      width: CONTENT_WIDTH,
      lineGap: 2,
    });
    doc.moveDown(0.45);
  });
}

function drawFindingCard(doc, finding, index) {
  const title = `${index + 1}. ${finding.title}`;
  const evidence = safeText(finding.evidence, "No evidence captured.");
  const remediation = safeText(finding.remediation, "Review and remediate according to application context.");
  const titleHeight = doc.heightOfString(title, { width: 350 });
  const evidenceHeight = Math.min(44, doc.heightOfString(evidence, { width: 214 }));
  const remediationHeight = doc.heightOfString(remediation, { width: 464 });
  const cardHeight = Math.max(120, titleHeight + evidenceHeight + remediationHeight + 66);

  ensureSpace(doc, cardHeight + 12);
  const y = doc.y;
  doc.roundedRect(PAGE_MARGIN, y, CONTENT_WIDTH, cardHeight, 10).fillAndStroke("#fffdfa", "#dfe4dc");
  doc.fillColor(SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info)
    .font("Helvetica-Bold")
    .fontSize(10.5)
    .text(title, PAGE_MARGIN + 14, y + 14, { width: 350 });
  doc.fillColor("#6f736c")
    .font("Helvetica")
    .fontSize(8.5)
    .text(`${safeText(finding.severity).toUpperCase()} | ${safeText(finding.category)} | confidence ${finding.confidence || "--"}%`, PAGE_MARGIN + 14, y + 36 + titleHeight, { width: 350 });
  doc.text(`Affected: ${safeText(finding.location, "Global")}`, PAGE_MARGIN + 14, y + 52 + titleHeight, { width: 350 });
  doc.fillColor("#242521").font("Helvetica-Bold").fontSize(8).text("Evidence", PAGE_MARGIN + 278, y + 14);
  doc.fillColor("#4f574f").font("Helvetica").fontSize(8).text(evidence, PAGE_MARGIN + 278, y + 28, { width: 214, height: 48 });
  doc.fillColor("#242521").font("Helvetica-Bold").fontSize(8).text("Remediation", PAGE_MARGIN + 14, y + cardHeight - remediationHeight - 24);
  doc.fillColor("#4f574f").font("Helvetica").fontSize(8.7).text(remediation, PAGE_MARGIN + 14, y + cardHeight - remediationHeight - 10, { width: 464, lineGap: 1 });
  doc.y = y + cardHeight + 12;
}

async function buildPdfBuffer(scan) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: PAGE_MARGIN, size: "A4", bufferPages: true });
    const chunks = [];

    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    drawHeader(doc, scan);
    drawSectionTitle(doc, "Executive Summary");
    doc.font("Helvetica").fontSize(10.5).fillColor("#4f574f").text(safeText(scan.report?.executiveSummary, "No executive summary available."), PAGE_MARGIN, doc.y, {
      width: CONTENT_WIDTH,
      lineGap: 3,
    });
    doc.moveDown(1.2);
    drawMetadata(doc, scan);
    drawSeverityBars(doc, scan.summary?.bySeverity || {});
    drawRecommendations(doc, scan);

    doc.addPage();
    doc.y = PAGE_MARGIN;
    drawSectionTitle(doc, "Findings Detail");

    if (!scan.findings?.length) {
      doc.font("Helvetica").fontSize(10).fillColor("#4f574f").text("No findings were recorded for this passive scan.");
    } else {
      scan.findings.forEach((finding, index) => drawFindingCard(doc, finding, index));
    }

    const range = doc.bufferedPageRange();
    for (let index = range.start; index < range.start + range.count; index += 1) {
      doc.switchToPage(index);
      drawPageFooter(doc, index - range.start + 1, range.count);
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