const state = {
  token: localStorage.getItem("sentinelToken") || "",
  user: null,
  scans: [],
  metrics: {
    totalScans: 0,
    averageRisk: 0,
    riskTrend: [],
  },
  activeScan: null,
  filters: {
    severity: "all",
    category: "all",
    query: "",
  },
};

const authPanel = document.querySelector("#auth-panel");
const dashboard = document.querySelector("#dashboard");
const authMessage = document.querySelector("#auth-message");
const loginForm = document.querySelector("#login-form");
const signupForm = document.querySelector("#signup-form");
const showLogin = document.querySelector("#show-login");
const showSignup = document.querySelector("#show-signup");
const userGreeting = document.querySelector("#user-greeting");
const storageMode = document.querySelector("#storage-mode");
const logoutButton = document.querySelector("#logout-button");
const themeToggle = document.querySelector("#theme-toggle");
const statusBanner = document.querySelector("#status-banner");
const statusSpinner = document.querySelector("#status-spinner");
const statusText = document.querySelector("#status-text");
const form = document.querySelector("#scan-form");
const scanButton = document.querySelector("#scan-button");
const includeSubpages = document.querySelector("#include-subpages");
const maxPages = document.querySelector("#max-pages");
const riskBand = document.querySelector("#risk-band");
const riskScore = document.querySelector("#risk-score");
const findingTotal = document.querySelector("#finding-total");
const pagesCrawled = document.querySelector("#pages-crawled");
const totalScans = document.querySelector("#total-scans");
const averageRisk = document.querySelector("#average-risk");
const scanDuration = document.querySelector("#scan-duration");
const severityChart = document.querySelector("#severity-chart");
const severityBreakdown = document.querySelector("#severity-breakdown");
const riskTrend = document.querySelector("#risk-trend");
const historyList = document.querySelector("#history-list");
const reportContent = document.querySelector("#report-content");
const aiContent = document.querySelector("#ai-content");
const refreshAi = document.querySelector("#refresh-ai");
const categoryFilter = document.querySelector("#category-filter");
const severityFilter = document.querySelector("#severity-filter");
const searchFilter = document.querySelector("#search-filter");
const filterResults = document.querySelector("#filter-results");
const coverageContent = document.querySelector("#coverage-content");
const findingsList = document.querySelector("#findings-list");
const downloadPdf = document.querySelector("#download-pdf");
const downloadTxt = document.querySelector("#download-txt");
const downloadMd = document.querySelector("#download-md");
const downloadJson = document.querySelector("#download-json");
const downloadHtml = document.querySelector("#download-html");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setTheme(theme) {
  document.body.dataset.theme = theme;
  localStorage.setItem("sentinelTheme", theme);
}

function toggleTheme() {
  setTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
}

function setStatus(type, message) {
  statusBanner.className = `status-banner ${type}`;
  statusSpinner.hidden = type !== "loading";
  statusText.textContent = message;
}

function setAuthMessage(message, type = "info") {
  authMessage.textContent = message;
  authMessage.dataset.type = type;
}

function setToken(token) {
  state.token = token || "";

  if (state.token) {
    localStorage.setItem("sentinelToken", state.token);
  } else {
    localStorage.removeItem("sentinelToken");
  }
}

function authHeaders(extra = {}) {
  return state.token
    ? {
        ...extra,
        Authorization: `Bearer ${state.token}`,
      }
    : extra;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: authHeaders({
      ...(options.headers || {}),
    }),
  });

  const payload = await response.json();

  if (!response.ok) {
    throw new Error(payload.error || "Request failed.");
  }

  return payload;
}

function switchAuthMode(mode) {
  loginForm.classList.toggle("hidden", mode !== "login");
  signupForm.classList.toggle("hidden", mode !== "signup");
  showLogin.classList.toggle("active", mode === "login");
  showSignup.classList.toggle("active", mode === "signup");
}

function setAuthenticated(isAuthenticated) {
  authPanel.classList.toggle("hidden", isAuthenticated);
  dashboard.classList.toggle("hidden", !isAuthenticated);
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "Unknown time";
}

function formatDuration(durationMs) {
  if (!Number.isFinite(durationMs) || durationMs <= 0) {
    return "--";
  }

  if (durationMs < 1000) {
    return `${durationMs} ms`;
  }

  return `${(durationMs / 1000).toFixed(1)} s`;
}

function getSeverityColor(severity) {
  return {
    critical: "#ff4d67",
    high: "#ff8a4c",
    medium: "#e9b44c",
    low: "#41d19a",
    info: "#77a8ff",
  }[severity] || "#77a8ff";
}

function updateDownloadButtons(enabled) {
  [downloadPdf, downloadTxt, downloadMd, downloadJson, downloadHtml, refreshAi].forEach((button) => {
    button.disabled = !enabled;
  });
}

function renderSeverityChart(bySeverity = {}) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = Object.values(bySeverity).reduce((sum, count) => sum + count, 0);

  if (!total) {
    severityChart.className = "severity-chart empty";
    severityChart.style.background = "";
    severityChart.textContent = "Awaiting scan";
    severityBreakdown.className = "severity-breakdown empty";
    severityBreakdown.textContent = "Run a scan to view severity distribution.";
    return;
  }

  let cursor = 0;
  const slices = order
    .filter((severity) => bySeverity[severity])
    .map((severity) => {
      const slice = (bySeverity[severity] / total) * 100;
      const segment = `${getSeverityColor(severity)} ${cursor}% ${cursor + slice}%`;
      cursor += slice;
      return segment;
    });

  severityChart.className = "severity-chart";
  severityChart.style.background = `conic-gradient(${slices.join(", ")})`;
  severityChart.innerHTML = `<span><strong>${total}</strong><small>Findings</small></span>`;
  severityBreakdown.className = "severity-breakdown";
  severityBreakdown.innerHTML = order
    .filter((severity) => bySeverity[severity])
    .map(
      (severity) =>
        `<span class="severity-chip ${severity}">${escapeHtml(severity.toUpperCase())}: ${escapeHtml(bySeverity[severity])}</span>`,
    )
    .join("");
}

function renderTrendChart(trend = []) {
  if (!trend.length) {
    riskTrend.className = "risk-trend empty";
    riskTrend.textContent = "No scan history yet.";
    return;
  }

  riskTrend.className = "risk-trend";
  riskTrend.innerHTML = trend
    .map((point) => {
      const height = Math.max(14, Math.min(180, Math.round((point.riskScore / 100) * 180)));
      return `
        <div class="trend-bar" style="height:${height}px">
          <span>${escapeHtml(new Date(point.scannedAt).toLocaleDateString())}</span>
        </div>
      `;
    })
    .join("");
}

function renderHistory() {
  totalScans.textContent = String(state.metrics.totalScans || state.scans.length);
  averageRisk.textContent = String(state.metrics.averageRisk || 0);
  renderTrendChart(state.metrics.riskTrend || []);

  if (!state.scans.length) {
    historyList.className = "history-list empty";
    historyList.textContent = "No scans yet.";
    return;
  }

  historyList.className = "history-list";
  historyList.innerHTML = state.scans
    .map((scan) => {
      const active = state.activeScan?.id === scan.id ? " active" : "";
      return `
        <button class="history-item${active}" type="button" data-scan-id="${escapeHtml(scan.id)}">
          <div class="history-topline">
            <div>
              <strong>${escapeHtml(new URL(scan.finalUrl || scan.target).hostname)}</strong>
              <span class="history-meta">${escapeHtml(formatDate(scan.scannedAt))}</span>
            </div>
            <span class="chip ${escapeHtml(scan.risk.band.toLowerCase())}">${escapeHtml(scan.risk.band)}</span>
          </div>
          <span class="history-meta">${escapeHtml(scan.summary.total)} findings across ${escapeHtml(scan.coverage.pagesCrawled)} page(s)</span>
          <span class="history-meta">Duration: ${escapeHtml(formatDuration(scan.durationMs))}</span>
        </button>
      `;
    })
    .join("");
}

function renderSummary(scan) {
  if (!scan) {
    riskBand.textContent = "No Data";
    riskBand.className = "chip neutral";
    riskScore.textContent = "--";
    findingTotal.textContent = "--";
    pagesCrawled.textContent = "--";
    scanDuration.textContent = "--";
    renderSeverityChart({});
    return;
  }

  riskBand.textContent = scan.risk.band;
  riskBand.className = `chip ${scan.risk.band.toLowerCase()}`;
  riskScore.textContent = `${scan.risk.score}/100`;
  findingTotal.textContent = String(scan.summary.total);
  pagesCrawled.textContent = String(scan.coverage.pagesCrawled);
  scanDuration.textContent = formatDuration(scan.durationMs);
  renderSeverityChart(scan.summary.bySeverity);
}

function renderReport(scan) {
  if (!scan) {
    reportContent.className = "report-content empty";
    reportContent.textContent = "Run a scan to generate a report.";
    return;
  }

  const metadataRows = [
    ["Target", scan.target],
    ["Final URL", scan.finalUrl],
    ["Scanned", formatDate(scan.scannedAt)],
    ["Duration", formatDuration(scan.durationMs)],
  ]
    .map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`)
    .join("");

  const findingsRows = scan.findings
    .slice(0, 8)
    .map(
      (finding) => `
        <tr>
          <td><span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
          <td>${escapeHtml(finding.title)}</td>
          <td>${escapeHtml(finding.category)}</td>
          <td>${escapeHtml(finding.location || "Global")}</td>
        </tr>
      `,
    )
    .join("");

  reportContent.className = "report-content";
  reportContent.innerHTML = `
    <article class="report-block">
      <h3>Executive Summary</h3>
      <p>${escapeHtml(scan.report.executiveSummary)}</p>
      <p class="supporting-copy">${escapeHtml(scan.report.threatNarrative)}</p>
    </article>
    <article class="report-block">
      <h3>Scan Metadata</h3>
      <table class="finding-table">
        <tbody>${metadataRows}</tbody>
      </table>
    </article>
    <article class="report-block">
      <h3>Recommendations</h3>
      <ol>
        ${(scan.report.priorityActions || [])
          .map((action) => `<li>${escapeHtml(action.action)} <span class="supporting-copy">${escapeHtml(action.reason)}</span></li>`)
          .join("")}
      </ol>
    </article>
    <article class="report-block">
      <h3>Findings Table</h3>
      <table class="finding-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Category</th>
            <th>Location</th>
          </tr>
        </thead>
        <tbody>${findingsRows}</tbody>
      </table>
    </article>
  `;
}

function renderAiContent(aiAssist) {
  if (!aiAssist) {
    aiContent.className = "report-content empty";
    aiContent.textContent = "AI explanations will appear here for the selected scan.";
    return;
  }

  aiContent.className = "report-content";
  aiContent.innerHTML = `
    <article class="report-block">
      <h3>Summary</h3>
      <p>${escapeHtml(aiAssist.summary)}</p>
    </article>
    <article class="report-block">
      <h3>Remediation Plan</h3>
      <ol>
        ${(aiAssist.remediationPlan || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ol>
    </article>
    ${(aiAssist.findingExplanations || [])
      .map(
        (item) => `
          <article class="report-block">
            <h3>${escapeHtml(item.title)}</h3>
            <p>${escapeHtml(item.simpleExplanation)}</p>
            <p class="supporting-copy">${escapeHtml(item.whyItMatters)}</p>
            <p><strong>Suggested fix:</strong> ${escapeHtml(item.suggestedFix)}</p>
          </article>
        `,
      )
      .join("")}
  `;
}

function renderCoverage(scan) {
  if (!scan) {
    coverageContent.className = "coverage-content empty";
    coverageContent.textContent = "No coverage data yet.";
    return;
  }

  coverageContent.className = "coverage-content";
  coverageContent.innerHTML = `
    <article class="report-block">
      <h3>Inventory</h3>
      <div class="inventory-grid">
        <div class="inventory-card">
          <span>Forms</span>
          <strong>${escapeHtml(scan.inventory.totalForms)}</strong>
        </div>
        <div class="inventory-card">
          <span>Password Surfaces</span>
          <strong>${escapeHtml(scan.inventory.totalPasswordForms)}</strong>
        </div>
        <div class="inventory-card">
          <span>Script Hosts</span>
          <strong>${escapeHtml(scan.inventory.externalScriptHosts.length)}</strong>
        </div>
      </div>
      <div class="pill-row">
        ${(scan.inventory.externalScriptHosts || []).length
          ? scan.inventory.externalScriptHosts.map((host) => `<span class="meta-pill">${escapeHtml(host)}</span>`).join("")
          : '<span class="meta-pill">No external script hosts detected</span>'}
      </div>
    </article>
    <div class="pages-grid">
      ${scan.coverage.pages
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
              </div>
            </article>
          `,
        )
        .join("")}
    </div>
  `;
}

function getFilteredFindings() {
  if (!state.activeScan) {
    return [];
  }

  return state.activeScan.findings.filter((finding) => {
    const severityMatch = state.filters.severity === "all" || finding.severity === state.filters.severity;
    const categoryMatch = state.filters.category === "all" || finding.category === state.filters.category;
    const query = state.filters.query.toLowerCase();
    const haystack = `${finding.title} ${finding.description} ${finding.evidence} ${finding.location || ""}`.toLowerCase();
    const queryMatch = !query || haystack.includes(query);
    return severityMatch && categoryMatch && queryMatch;
  });
}

function renderFindings() {
  if (!state.activeScan) {
    findingsList.className = "findings-list empty";
    findingsList.textContent = "No findings to display yet.";
    filterResults.textContent = "Showing 0 findings.";
    return;
  }

  const filtered = getFilteredFindings();
  filterResults.textContent = `Showing ${filtered.length} of ${state.activeScan.findings.length} findings.`;

  if (!filtered.length) {
    findingsList.className = "findings-list empty";
    findingsList.textContent = "No findings match the selected filters.";
    return;
  }

  findingsList.className = "findings-list";
  findingsList.innerHTML = filtered
    .map(
      (finding) => `
        <article class="finding-card">
          <div class="finding-topline">
            <h3>${escapeHtml(finding.title)}</h3>
            <span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          </div>
          <div class="finding-meta">
            <span class="meta-pill">${escapeHtml(finding.category)}</span>
            <span class="meta-pill">${escapeHtml(finding.location || "Global")}</span>
          </div>
          <div class="finding-sections">
            <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
            <p><strong>Impact:</strong> ${escapeHtml(finding.impact)}</p>
            <p><strong>Recommendation:</strong> ${escapeHtml(finding.remediation)}</p>
            <p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p>
          </div>
        </article>
      `,
    )
    .join("");
}

function renderCategoryFilter(scan) {
  const categories = scan ? Object.keys(scan.summary.byCategory || {}).sort() : [];
  categoryFilter.innerHTML = `
    <option value="all">All categories</option>
    ${categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join("")}
  `;
}

function updateDashboard(scan) {
  state.activeScan = scan;
  renderSummary(scan);
  renderReport(scan);
  renderCoverage(scan);
  renderAiContent(scan?.aiAssist || null);
  renderCategoryFilter(scan);
  renderFindings();
  updateDownloadButtons(Boolean(scan));
  renderHistory();
}

async function loadHealth() {
  const payload = await fetchJson("/api/health");
  storageMode.textContent = payload.storageMode;
}

async function loadMe() {
  if (!state.token) {
    setAuthenticated(false);
    return;
  }

  try {
    const payload = await fetchJson("/api/auth/me");
    state.user = payload.user;
    userGreeting.textContent = `Welcome, ${payload.user.name}`;
    setAuthenticated(true);
    await Promise.all([loadHealth(), loadScans()]);
  } catch {
    setToken("");
    state.user = null;
    setAuthenticated(false);
  }
}

async function loadScans() {
  const payload = await fetchJson("/api/scans");
  state.scans = payload.scans || [];
  state.metrics = payload.metrics || state.metrics;
  renderHistory();

  if (state.scans.length && !state.activeScan) {
    await loadScan(state.scans[0].id, false);
  }
}

async function loadScan(scanId, announce = true) {
  const scan = await fetchJson(`/api/scans/${encodeURIComponent(scanId)}`);
  updateDashboard(scan);

  if (announce) {
    setStatus("success", `Loaded saved scan for ${scan.finalUrl}.`);
  }
}

async function loadAiAssist(scanId) {
  const payload = await fetchJson(`/api/scans/${encodeURIComponent(scanId)}/ai`);
  renderAiContent(payload.aiAssist);
}

function downloadBlob(blob, filename) {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}

async function downloadReport(format) {
  if (!state.activeScan) {
    return;
  }

  const response = await fetch(`/api/reports/${encodeURIComponent(state.activeScan.id)}/${format}`, {
    headers: authHeaders(),
  });

  if (!response.ok) {
    const payload = await response.json();
    throw new Error(payload.error || "Unable to export report.");
  }

  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") || "";
  const filenameMatch = disposition.match(/filename="(.+)"/);
  const filename = filenameMatch ? filenameMatch[1] : `sentinel-scan-report.${format}`;
  downloadBlob(blob, filename);
}

function buildHtmlSnapshot(scan) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Sentinel Scan HTML Snapshot</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 32px; line-height: 1.6; color: #10223c; }
      .card { border: 1px solid #dbe5f0; border-radius: 14px; padding: 16px; margin-bottom: 16px; }
    </style>
  </head>
  <body>
    <h1>Sentinel Scan Report Snapshot</h1>
    <p><strong>Target:</strong> ${escapeHtml(scan.target)}</p>
    <p><strong>Risk:</strong> ${escapeHtml(scan.risk.score)}/100 (${escapeHtml(scan.risk.band)})</p>
    <p><strong>Scanned:</strong> ${escapeHtml(formatDate(scan.scannedAt))}</p>
    <div class="card">
      <h2>Executive Summary</h2>
      <p>${escapeHtml(scan.report.executiveSummary)}</p>
    </div>
    ${scan.findings
      .map(
        (finding) => `
          <div class="card">
            <h3>${escapeHtml(finding.title)}</h3>
            <p><strong>Severity:</strong> ${escapeHtml(finding.severity)}</p>
            <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
            <p><strong>Recommendation:</strong> ${escapeHtml(finding.remediation)}</p>
          </div>
        `,
      )
      .join("")}
  </body>
</html>`;
}

showLogin.addEventListener("click", () => switchAuthMode("login"));
showSignup.addEventListener("click", () => switchAuthMode("signup"));
themeToggle.addEventListener("click", toggleTheme);

logoutButton.addEventListener("click", () => {
  setToken("");
  state.user = null;
  state.scans = [];
  state.metrics = { totalScans: 0, averageRisk: 0, riskTrend: [] };
  state.activeScan = null;
  updateDashboard(null);
  setAuthenticated(false);
  setStatus("idle", "Signed out. Login to continue.");
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    setAuthMessage("Logging in...", "info");
    const payload = await fetchJson("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(loginForm))),
    });
    setToken(payload.token);
    state.user = payload.user;
    userGreeting.textContent = `Welcome, ${payload.user.name}`;
    setAuthenticated(true);
    setAuthMessage("Login successful.", "success");
    await Promise.all([loadHealth(), loadScans()]);
  } catch (error) {
    setAuthMessage(error.message || "Unable to login.", "error");
  }
});

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    setAuthMessage("Creating account...", "info");
    const payload = await fetchJson("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(signupForm))),
    });
    setToken(payload.token);
    state.user = payload.user;
    userGreeting.textContent = `Welcome, ${payload.user.name}`;
    setAuthenticated(true);
    setAuthMessage("Account created successfully.", "success");
    await Promise.all([loadHealth(), loadScans()]);
  } catch (error) {
    setAuthMessage(error.message || "Unable to create account.", "error");
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = String(new FormData(form).get("url") || "").trim();

  if (!url) {
    setStatus("error", "Enter a target URL before starting the scan.");
    return;
  }

  scanButton.disabled = true;
  setStatus("loading", "Running a passive scan and collecting same-origin coverage.");

  try {
    const payload = await fetchJson("/api/scans", {
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

    state.scans = [
      {
        id: payload.id,
        target: payload.target,
        finalUrl: payload.finalUrl,
        scannedAt: payload.scannedAt,
        durationMs: payload.durationMs,
        risk: payload.risk,
        summary: payload.summary,
        coverage: { pagesCrawled: payload.coverage.pagesCrawled },
      },
      ...state.scans.filter((scan) => scan.id !== payload.id),
    ];

    state.metrics.totalScans = state.scans.length;
    state.metrics.averageRisk =
      state.scans.length > 0
        ? Math.round(state.scans.reduce((sum, scan) => sum + (scan.risk?.score || 0), 0) / state.scans.length)
        : 0;
    state.metrics.riskTrend = [
      ...state.scans.slice(0, 10).map((scan) => ({
        scannedAt: scan.scannedAt,
        riskScore: scan.risk.score,
        findings: scan.summary.total,
      })),
    ].reverse();

    updateDashboard(payload);
    setStatus("success", `Scan complete for ${payload.finalUrl}. Review findings and export the report.`);
  } catch (error) {
    setStatus("error", error.message || "Scan failed.");
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
    setStatus("loading", "Loading saved scan.");
    await loadScan(button.dataset.scanId);
  } catch (error) {
    setStatus("error", error.message || "Unable to load the selected scan.");
  }
});

refreshAi.addEventListener("click", async () => {
  if (!state.activeScan) {
    return;
  }

  try {
    setStatus("loading", "Refreshing AI explanations.");
    await loadAiAssist(state.activeScan.id);
    setStatus("success", "AI explanations refreshed.");
  } catch (error) {
    setStatus("error", error.message || "Unable to load AI explanations.");
  }
});

severityFilter.addEventListener("change", () => {
  state.filters.severity = severityFilter.value;
  renderFindings();
});

categoryFilter.addEventListener("change", () => {
  state.filters.category = categoryFilter.value;
  renderFindings();
});

searchFilter.addEventListener("input", () => {
  state.filters.query = searchFilter.value.trim();
  renderFindings();
});

downloadPdf.addEventListener("click", () => downloadReport("pdf").catch((error) => setStatus("error", error.message)));
downloadTxt.addEventListener("click", () => downloadReport("txt").catch((error) => setStatus("error", error.message)));
downloadMd.addEventListener("click", () => downloadReport("md").catch((error) => setStatus("error", error.message)));
downloadJson.addEventListener("click", () => downloadReport("json").catch((error) => setStatus("error", error.message)));
downloadHtml.addEventListener("click", () => {
  if (!state.activeScan) {
    return;
  }

  const blob = new Blob([buildHtmlSnapshot(state.activeScan)], { type: "text/html" });
  downloadBlob(blob, "sentinel-scan-snapshot.html");
});

const savedTheme = localStorage.getItem("sentinelTheme");
if (savedTheme) {
  setTheme(savedTheme);
}

statusSpinner.hidden = true;
setAuthenticated(false);
updateDownloadButtons(false);
switchAuthMode("login");
renderSummary(null);
renderHistory();
renderReport(null);
renderAiContent(null);
renderCoverage(null);
renderFindings();

loadMe().catch(() => {
  setAuthenticated(false);
});
