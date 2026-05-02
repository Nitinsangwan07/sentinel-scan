const state = {
  history: [],
  activeScan: null,
  filters: {
    severity: "all",
    category: "all",
    query: "",
  },
};

const form = document.querySelector("#scan-form");
const statusBanner = document.querySelector("#status-banner");
const scanButton = document.querySelector("#scan-button");
const riskBand = document.querySelector("#risk-band");
const riskScore = document.querySelector("#risk-score");
const findingTotal = document.querySelector("#finding-total");
const pagesCrawled = document.querySelector("#pages-crawled");
const formsObserved = document.querySelector("#forms-observed");
const scriptHosts = document.querySelector("#script-hosts");
const finalUrl = document.querySelector("#final-url");
const severityBreakdown = document.querySelector("#severity-breakdown");
const reportContent = document.querySelector("#report-content");
const coverageContent = document.querySelector("#coverage-content");
const findingsList = document.querySelector("#findings-list");
const historyList = document.querySelector("#history-list");
const categoryFilter = document.querySelector("#category-filter");
const severityFilter = document.querySelector("#severity-filter");
const searchFilter = document.querySelector("#search-filter");
const includeSubpages = document.querySelector("#include-subpages");
const maxPages = document.querySelector("#max-pages");
const downloadJson = document.querySelector("#download-json");
const downloadMd = document.querySelector("#download-md");
const downloadHtml = document.querySelector("#download-html");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setStatus(type, message) {
  statusBanner.className = `status-banner ${type}`;
  statusBanner.textContent = message;
}

function formatDate(value) {
  if (!value) {
    return "Unknown time";
  }

  return new Date(value).toLocaleString();
}

function setDownloadsEnabled(enabled) {
  downloadJson.disabled = !enabled;
  downloadMd.disabled = !enabled;
  downloadHtml.disabled = !enabled;
}

function formatSeverityEntries(bySeverity = {}) {
  const order = ["critical", "high", "medium", "low", "info"];
  const entries = order.filter((severity) => bySeverity[severity]);

  if (entries.length === 0) {
    severityBreakdown.className = "severity-breakdown empty";
    severityBreakdown.textContent = "No findings were reported for this scan.";
    return;
  }

  severityBreakdown.className = "severity-breakdown";
  severityBreakdown.innerHTML = entries
    .map(
      (severity) =>
        `<span class="severity-chip ${severity}">${escapeHtml(severity.toUpperCase())}: ${escapeHtml(bySeverity[severity])}</span>`,
    )
    .join("");
}

function renderHistory() {
  if (!state.history.length) {
    historyList.className = "history-list empty";
    historyList.textContent = "No saved scans yet. Run your first scan to populate this workspace.";
    return;
  }

  historyList.className = "history-list";
  historyList.innerHTML = state.history
    .map((scan) => {
      const active = state.activeScan?.id === scan.id ? " active" : "";
      return `
        <button class="history-item${active}" type="button" data-scan-id="${escapeHtml(scan.id)}">
          <span class="history-topline">
            <strong>${escapeHtml(new URL(scan.finalUrl || scan.target).hostname)}</strong>
            <span class="score-pill ${escapeHtml(scan.risk.band.toLowerCase())}">${escapeHtml(scan.risk.band)}</span>
          </span>
          <span class="history-meta">${escapeHtml(formatDate(scan.scannedAt))}</span>
          <span class="history-meta">${escapeHtml(scan.summary.total)} findings across ${escapeHtml(scan.coverage.pagesCrawled)} page(s)</span>
        </button>
      `;
    })
    .join("");
}

function renderReport(scan) {
  if (!scan) {
    reportContent.className = "report-content empty";
    reportContent.textContent = "Your remediation narrative will appear here after the first scan.";
    return;
  }

  const priorityActions = scan.report.priorityActions
    .map(
      (action) => `
        <li>
          <strong>P${escapeHtml(action.priority)}:</strong> ${escapeHtml(action.action)}
          <br />
          <span>${escapeHtml(action.reason)}</span>
        </li>
      `,
    )
    .join("");

  const quickWins = (scan.report.quickWins || [])
    .map((action) => `<li>${escapeHtml(action)}</li>`)
    .join("");

  const technologies = (scan.technologies || []).length
    ? scan.technologies.map((entry) => `<span class="meta-pill">${escapeHtml(entry)}</span>`).join("")
    : `<span class="meta-pill">No strong framework fingerprint</span>`;

  reportContent.className = "report-content";
  reportContent.innerHTML = `
    <article class="report-block">
      <h3>Executive Summary</h3>
      <p>${escapeHtml(scan.report.executiveSummary)}</p>
    </article>
    <article class="report-block">
      <h3>Threat Narrative</h3>
      <p>${escapeHtml(scan.report.threatNarrative)}</p>
    </article>
    <article class="report-block">
      <h3>Coverage Notes</h3>
      <p>${escapeHtml(scan.report.coverageNotes)}</p>
      <p class="supporting-copy">${escapeHtml(scan.report.attackSurface)}</p>
    </article>
    <article class="report-block">
      <h3>Priority Actions</h3>
      <ol>${priorityActions || "<li>No urgent actions were generated.</li>"}</ol>
    </article>
    <article class="report-block">
      <h3>Quick Wins</h3>
      <ul>${quickWins || "<li>No immediate quick wins were generated.</li>"}</ul>
    </article>
    <article class="report-block">
      <h3>Detected Technologies</h3>
      <div class="pill-row">${technologies}</div>
    </article>
  `;
}

function renderCoverage(scan) {
  if (!scan) {
    coverageContent.className = "coverage-content empty";
    coverageContent.textContent = "No page coverage data yet.";
    return;
  }

  const pages = scan.coverage.pages
    .map(
      (page) => `
        <article class="page-card">
          <div class="page-topline">
            <h3>${escapeHtml(page.title)}</h3>
            <span class="meta-pill">HTTP ${escapeHtml(page.status)}</span>
          </div>
          <p class="page-url">${escapeHtml(page.url)}</p>
          <div class="page-stats">
            <span class="meta-pill">Forms ${escapeHtml(page.formsCount)}</span>
            <span class="meta-pill">Password ${escapeHtml(page.passwordForms)}</span>
            <span class="meta-pill">Inline Scripts ${escapeHtml(page.inlineScriptCount)}</span>
            <span class="meta-pill">Internal Links ${escapeHtml(page.internalLinks)}</span>
            <span class="meta-pill">Findings ${escapeHtml(page.findingsCount)}</span>
          </div>
          <div class="pill-row">
            ${(page.externalScriptHosts || []).length
              ? page.externalScriptHosts.map((host) => `<span class="meta-pill">${escapeHtml(host)}</span>`).join("")
              : '<span class="meta-pill">No third-party scripts</span>'}
          </div>
        </article>
      `,
    )
    .join("");

  const inventoryHosts = scan.inventory.externalScriptHosts.length
    ? scan.inventory.externalScriptHosts.map((host) => `<span class="meta-pill">${escapeHtml(host)}</span>`).join("")
    : '<span class="meta-pill">No external script hosts observed</span>';

  const loginPages = scan.inventory.loginPages.length
    ? scan.inventory.loginPages.map((url) => `<li>${escapeHtml(url)}</li>`).join("")
    : "<li>No login-like paths were observed in the crawled set.</li>";

  coverageContent.className = "coverage-content";
  coverageContent.innerHTML = `
    <article class="report-block">
      <h3>Attack Surface Inventory</h3>
      <p>${escapeHtml(scan.report.attackSurface)}</p>
      <div class="inventory-grid">
        <div class="inventory-card">
          <span>Total Forms</span>
          <strong>${escapeHtml(scan.inventory.totalForms)}</strong>
        </div>
        <div class="inventory-card">
          <span>Password Surfaces</span>
          <strong>${escapeHtml(scan.inventory.totalPasswordForms)}</strong>
        </div>
        <div class="inventory-card">
          <span>Pages Crawled</span>
          <strong>${escapeHtml(scan.coverage.pagesCrawled)}</strong>
        </div>
      </div>
      <div class="pill-row">${inventoryHosts}</div>
    </article>
    <article class="report-block">
      <h3>Login-Like Pages</h3>
      <ul>${loginPages}</ul>
    </article>
    <div class="pages-grid">
      ${pages}
    </div>
  `;
}

function getFilteredFindings(scan) {
  return scan.findings.filter((finding) => {
    const matchesSeverity =
      state.filters.severity === "all" || finding.severity === state.filters.severity;
    const matchesCategory =
      state.filters.category === "all" || finding.category === state.filters.category;
    const haystack = `${finding.title} ${finding.description} ${finding.evidence} ${finding.location || ""}`.toLowerCase();
    const matchesQuery =
      !state.filters.query || haystack.includes(state.filters.query.toLowerCase());

    return matchesSeverity && matchesCategory && matchesQuery;
  });
}

function renderFindings(scan) {
  if (!scan) {
    findingsList.className = "findings-list empty";
    findingsList.textContent = "No findings to display yet.";
    return;
  }

  const filtered = getFilteredFindings(scan);

  if (!filtered.length) {
    findingsList.className = "findings-list empty";
    findingsList.textContent = "No findings match the current filters.";
    return;
  }

  findingsList.className = "findings-list";
  findingsList.innerHTML = filtered
    .map(
      (finding) => `
        <article class="finding-card">
          <div class="finding-topline">
            <h3>${escapeHtml(finding.title)}</h3>
            <span class="score-pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          </div>
          <div class="finding-meta">
            <span class="meta-pill">${escapeHtml(finding.category)}</span>
            <span class="meta-pill">${escapeHtml(finding.id)}</span>
            <span class="meta-pill">${escapeHtml(finding.location || "Global")}</span>
          </div>
          <div class="finding-sections">
            <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
            <p><strong>Impact:</strong> ${escapeHtml(finding.impact)}</p>
            <p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
            <p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p>
          </div>
        </article>
      `,
    )
    .join("");
}

function renderCategoryFilter(scan) {
  const categories = scan ? Object.keys(scan.summary.byCategory || {}).sort() : [];
  const nextValue = categories.includes(state.filters.category) ? state.filters.category : "all";

  categoryFilter.innerHTML = `
    <option value="all">All categories</option>
    ${categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join("")}
  `;
  categoryFilter.value = nextValue;
  state.filters.category = nextValue;
}

function renderSummary(scan) {
  if (!scan) {
    riskBand.textContent = "No Data";
    riskBand.className = "score-pill neutral";
    riskScore.textContent = "--";
    findingTotal.textContent = "--";
    pagesCrawled.textContent = "--";
    formsObserved.textContent = "--";
    scriptHosts.textContent = "--";
    finalUrl.textContent = "Waiting for scan";
    formatSeverityEntries({});
    return;
  }

  riskBand.textContent = scan.risk.band;
  riskBand.className = `score-pill ${scan.risk.band.toLowerCase()}`;
  riskScore.textContent = `${scan.risk.score}/100`;
  findingTotal.textContent = String(scan.summary.total);
  pagesCrawled.textContent = String(scan.coverage.pagesCrawled);
  formsObserved.textContent = String(scan.inventory.totalForms);
  scriptHosts.textContent = String(scan.inventory.externalScriptHosts.length);
  finalUrl.textContent = scan.finalUrl;
  formatSeverityEntries(scan.summary.bySeverity);
}

function updateActiveScan(scan) {
  state.activeScan = scan;
  renderSummary(scan);
  renderCategoryFilter(scan);
  renderReport(scan);
  renderCoverage(scan);
  renderFindings(scan);
  renderHistory();
  setDownloadsEnabled(Boolean(scan));
}

function downloadBlob(contents, filename, type) {
  const blob = new Blob([contents], { type });
  const anchor = document.createElement("a");
  const url = URL.createObjectURL(blob);
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildHtmlExport(scan) {
  const findings = scan.findings
    .map(
      (finding) => `
        <section style="margin-bottom:18px;padding:16px;border:1px solid #ddd;border-radius:14px;">
          <h3 style="margin:0 0 10px 0;">${escapeHtml(finding.title)}</h3>
          <p><strong>Severity:</strong> ${escapeHtml(finding.severity)}</p>
          <p><strong>Category:</strong> ${escapeHtml(finding.category)}</p>
          <p><strong>Location:</strong> ${escapeHtml(finding.location || "Global")}</p>
          <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
          <p><strong>Impact:</strong> ${escapeHtml(finding.impact)}</p>
          <p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
          <p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p>
        </section>
      `,
    )
    .join("");

  const pages = scan.coverage.pages
    .map(
      (page) => `
        <li>${escapeHtml(page.url)} | status ${escapeHtml(page.status)} | forms ${escapeHtml(page.formsCount)} | findings ${escapeHtml(page.findingsCount)}</li>
      `,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Sentinel Scan Report</title>
    <style>
      body { font-family: Georgia, serif; color: #1f1d1a; margin: 40px; line-height: 1.6; }
      .pill { display: inline-block; padding: 6px 10px; border-radius: 999px; background: #f0e5d8; margin-right: 8px; }
    </style>
  </head>
  <body>
    <h1>Sentinel Scan Report</h1>
    <p><strong>Target:</strong> ${escapeHtml(scan.target)}</p>
    <p><strong>Final URL:</strong> ${escapeHtml(scan.finalUrl)}</p>
    <p><strong>Scanned At:</strong> ${escapeHtml(scan.scannedAt)}</p>
    <p><strong>Risk Score:</strong> ${escapeHtml(scan.risk.score)}/100 (${escapeHtml(scan.risk.band)})</p>
    <p><strong>Summary:</strong> ${escapeHtml(scan.report.executiveSummary)}</p>
    <p><strong>Threat Narrative:</strong> ${escapeHtml(scan.report.threatNarrative)}</p>
    <p><strong>Attack Surface:</strong> ${escapeHtml(scan.report.attackSurface)}</p>
    <h2>Priority Actions</h2>
    <ol>
      ${scan.report.priorityActions
        .map(
          (action) => `<li>${escapeHtml(action.action)} (${escapeHtml(action.reason)})</li>`,
        )
        .join("")}
    </ol>
    <h2>Pages</h2>
    <ul>${pages}</ul>
    <h2>Findings</h2>
    ${findings}
  </body>
</html>`;
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json();

  if (!response.ok) {
    throw new Error(payload.error || "Request failed.");
  }

  return payload;
}

async function loadHistory(autoLoadLatest = true) {
  const payload = await fetchJson("/api/scans");
  state.history = payload.scans || [];
  renderHistory();

  if (autoLoadLatest && !state.activeScan && state.history.length) {
    await loadScan(state.history[0].id, false);
  }
}

async function loadScan(id, announce = true) {
  const scan = await fetchJson(`/api/scans/${encodeURIComponent(id)}`);
  updateActiveScan(scan);

  if (announce) {
    setStatus("success", `Loaded saved scan for ${scan.finalUrl}.`);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(form);
  const url = String(formData.get("url") || "").trim();

  if (!url) {
    setStatus("error", "Enter a website URL before launching the scan.");
    return;
  }

  scanButton.disabled = true;
  setStatus(
    "loading",
    "Running passive checks and collecting same-origin page coverage. This can take a few seconds.",
  );

  try {
    const payload = await fetchJson("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        options: {
          includeSubpages: includeSubpages.checked,
          maxPages: Number(maxPages.value),
        },
      }),
    });

    state.history = [payload, ...state.history.filter((scan) => scan.id !== payload.id)].map((scan) => ({
      id: scan.id,
      target: scan.target,
      finalUrl: scan.finalUrl,
      scannedAt: scan.scannedAt,
      risk: scan.risk,
      summary: scan.summary,
      options: scan.options,
      coverage: {
        pagesCrawled: scan.coverage.pagesCrawled,
      },
    }));
    updateActiveScan(payload);
    setStatus("success", `Scan complete for ${payload.finalUrl}. Review the findings, coverage, and saved history.`);
  } catch (error) {
    setStatus("error", error.message || "The scan could not be completed.");
  } finally {
    scanButton.disabled = false;
  }
});

historyList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-scan-id]");

  if (!button) {
    return;
  }

  try {
    setStatus("loading", "Loading the selected saved scan.");
    await loadScan(button.dataset.scanId);
  } catch (error) {
    setStatus("error", error.message || "Unable to load the selected scan.");
  }
});

severityFilter.addEventListener("change", () => {
  state.filters.severity = severityFilter.value;
  renderFindings(state.activeScan);
});

categoryFilter.addEventListener("change", () => {
  state.filters.category = categoryFilter.value;
  renderFindings(state.activeScan);
});

searchFilter.addEventListener("input", () => {
  state.filters.query = searchFilter.value.trim();
  renderFindings(state.activeScan);
});

includeSubpages.addEventListener("change", () => {
  maxPages.disabled = !includeSubpages.checked;
});

downloadJson.addEventListener("click", () => {
  if (!state.activeScan) {
    return;
  }

  const safeHost = new URL(state.activeScan.finalUrl).hostname.replace(/[^\w.-]+/g, "_");
  downloadBlob(JSON.stringify(state.activeScan, null, 2), `sentinel-scan-${safeHost}.json`, "application/json");
});

downloadMd.addEventListener("click", () => {
  if (!state.activeScan) {
    return;
  }

  const safeHost = new URL(state.activeScan.finalUrl).hostname.replace(/[^\w.-]+/g, "_");
  downloadBlob(state.activeScan.markdown, `sentinel-scan-${safeHost}.md`, "text/markdown");
});

downloadHtml.addEventListener("click", () => {
  if (!state.activeScan) {
    return;
  }

  const safeHost = new URL(state.activeScan.finalUrl).hostname.replace(/[^\w.-]+/g, "_");
  downloadBlob(buildHtmlExport(state.activeScan), `sentinel-scan-${safeHost}.html`, "text/html");
});

setDownloadsEnabled(false);
renderSummary(null);
renderReport(null);
renderCoverage(null);
renderFindings(null);

loadHistory().catch((error) => {
  setStatus("error", error.message || "Unable to load saved scans.");
});
