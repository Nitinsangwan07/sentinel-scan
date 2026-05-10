const SUPPORT_EMAIL = "gamerbuddy9090@gmail.com";


const state = {
  token: localStorage.getItem("sentinelToken") || sessionStorage.getItem("sentinelToken") || "",
  tokenStorage: localStorage.getItem("sentinelToken") ? "local" : sessionStorage.getItem("sentinelToken") ? "session" : "local",
  authConfig: { googleEnabled: false, googleClientId: "" },
  user: null,
  scans: [],
  activeScan: null,
  hasRevealedResults: false,
  metrics: {
    totalScans: 0,
    averageRisk: 0,
    riskTrend: [],
  },
  filters: {
    severity: "all",
    category: "all",
    query: "",
  },
};

const els = {
  authPanel: document.querySelector("#auth-panel"),
  introPanel: document.querySelector(".intro-panel"),
  dashboard: document.querySelector("#dashboard"),
  resultsArea: document.querySelector("#results-area"),
  historyPanel: document.querySelector("#history-panel"),
  authMessage: document.querySelector("#auth-message"),
  loginForm: document.querySelector("#login-form"),
  signupForm: document.querySelector("#signup-form"),
  showLogin: document.querySelector("#show-login"),
  showSignup: document.querySelector("#show-signup"),
  userGreeting: document.querySelector("#user-greeting"),
  storageMode: document.querySelector("#storage-mode"),
  logoutButton: document.querySelector("#logout-button"),
  themeToggle: document.querySelector("#theme-toggle"),
  statusBanner: document.querySelector("#status-banner"),
  statusSpinner: document.querySelector("#status-spinner"),
  statusText: document.querySelector("#status-text"),
  scanProgressFill: document.querySelector("#scan-progress-fill"),
  form: document.querySelector("#scan-form"),
  scanButton: document.querySelector("#scan-button"),
  includeSubpages: document.querySelector("#include-subpages"),
  maxPages: document.querySelector("#max-pages"),
  riskBand: document.querySelector("#risk-band"),
  riskScore: document.querySelector("#risk-score"),
  findingTotal: document.querySelector("#finding-total"),
  pagesCrawled: document.querySelector("#pages-crawled"),
  totalScans: document.querySelector("#total-scans"),
  averageRisk: document.querySelector("#average-risk"),
  scanDuration: document.querySelector("#scan-duration"),
  topCategory: document.querySelector("#top-category"),
  severityChart: document.querySelector("#severity-chart"),
  severityBreakdown: document.querySelector("#severity-breakdown"),
  riskTrend: document.querySelector("#risk-trend"),
  historyList: document.querySelector("#history-list"),
  reportContent: document.querySelector("#report-content"),
  aiContent: document.querySelector("#ai-content"),
  categoryFilter: document.querySelector("#category-filter"),
  severityFilter: document.querySelector("#severity-filter"),
  searchFilter: document.querySelector("#search-filter"),
  filterResults: document.querySelector("#filter-results"),
  coverageContent: document.querySelector("#coverage-content"),
  findingsList: document.querySelector("#findings-list"),
  activityFeed: document.querySelector("#activity-feed"),
  downloadPdf: document.querySelector("#download-pdf"),
  downloadTxt: document.querySelector("#download-txt"),
  downloadMd: document.querySelector("#download-md"),
  downloadJson: document.querySelector("#download-json"),
  downloadHtml: document.querySelector("#download-html"),
  googleAuthWrapper: document.querySelector("#google-auth-wrapper"),
  googleSigninButton: document.querySelector("#google-signin-button"),
  googleDisabledButton: document.querySelector("#google-disabled-button"),
  supportButton: document.querySelector("#support-button"),
  supportModal: document.querySelector("#support-modal"),
  supportClose: document.querySelector("#support-close"),
  supportForm: document.querySelector("#support-form"),
  supportSuccess: document.querySelector("#support-success"),
};

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

function clearSessionArtifacts() {
  localStorage.removeItem("sentinelToken");
  sessionStorage.removeItem("sentinelToken");
  document.cookie = "sentinelToken=; Max-Age=0; path=/";
  document.cookie = "token=; Max-Age=0; path=/";
  document.cookie = "authToken=; Max-Age=0; path=/";
}

function setToken(token, storage = "local") {
  state.token = token || "";
  state.tokenStorage = storage;
  clearSessionArtifacts();
  if (!token) return;
  (storage === "session" ? sessionStorage : localStorage).setItem("sentinelToken", token);
}

function setStatus(type, message) {
  els.statusBanner.className = `status-banner ${type}`;
  els.statusSpinner.hidden = type !== "loading";
  els.statusText.textContent = message;
}

function setProgress(percent) {
  if (!els.scanProgressFill) return;
  els.scanProgressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
}

function setAuthMessage(message, type = "info") {
  els.authMessage.textContent = message;
  els.authMessage.dataset.type = type;
}

function revealResults(shouldShow) {
  state.hasRevealedResults = Boolean(shouldShow);
  els.resultsArea?.classList.toggle("hidden", !shouldShow);
}

function revealHistory(shouldShow) {
  els.historyPanel?.classList.toggle("hidden", !shouldShow);
}

function setAuthenticated(isAuthenticated) {
  els.authPanel?.classList.toggle("hidden", isAuthenticated);
  els.introPanel?.classList.toggle("hidden", !isAuthenticated);
  els.dashboard?.classList.toggle("hidden", !isAuthenticated);
  document.body.dataset.authenticated = isAuthenticated ? "true" : "false";
}

function setLoadingSkeleton(isLoading) {
  [els.historyList, els.reportContent, els.coverageContent, els.findingsList, els.activityFeed].forEach((node) => {
    node?.classList.toggle("skeleton", isLoading);
  });
}

function authHeaders(extra = {}) {
  return state.token ? { ...extra, Authorization: `Bearer ${state.token}` } : extra;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: authHeaders({ ...(options.headers || {}) }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && state.token) {
      logout({ silent: true, message: "Your session expired. Please sign in again." });
    }
    throw new Error(payload.error || "Request failed.");
  }
  return payload;
}

function switchAuthMode(mode) {
  els.loginForm.classList.toggle("hidden", mode !== "login");
  els.signupForm.classList.toggle("hidden", mode !== "signup");
  els.showLogin.classList.toggle("active", mode === "login");
  els.showSignup.classList.toggle("active", mode === "signup");
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "Unknown time";
}

function formatDuration(durationMs) {
  if (!Number.isFinite(durationMs) || durationMs <= 0) return "--";
  return durationMs < 1000 ? `${durationMs} ms` : `${(durationMs / 1000).toFixed(1)} s`;
}

function getSeverityColor(severity) {
  return {
    critical: "#c7544f",
    high: "#d07a3a",
    medium: "#bc9544",
    low: "#348f6a",
    info: "#53789b",
  }[severity] || "#53789b";
}

function getTopCategory(scan) {
  const entries = Object.entries(scan?.summary?.byCategory || {}).sort((a, b) => b[1] - a[1]);
  return entries[0]?.[0] || "--";
}

function getHostname(scan) {
  const target = scan?.finalUrl || scan?.target || "";
  try {
    return new URL(target).hostname || target || "Unknown target";
  } catch {
    return target || "Unknown target";
  }
}

function updateDownloadButtons(enabled) {
  [els.downloadPdf, els.downloadTxt, els.downloadMd, els.downloadJson, els.downloadHtml].forEach((button) => {
    button.disabled = !enabled;
  });
}

function renderSeverityChart(bySeverity = {}) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = Object.values(bySeverity).reduce((sum, count) => sum + count, 0);
  if (!total) {
    els.severityChart.className = "severity-chart empty";
    els.severityChart.style.background = "";
    els.severityChart.textContent = "Awaiting scan";
    els.severityBreakdown.className = "severity-breakdown empty";
    els.severityBreakdown.textContent = "Run a scan to view severity distribution.";
    return;
  }

  let cursor = 0;
  const slices = order.filter((severity) => bySeverity[severity]).map((severity) => {
    const slice = (bySeverity[severity] / total) * 100;
    const segment = `${getSeverityColor(severity)} ${cursor}% ${cursor + slice}%`;
    cursor += slice;
    return segment;
  });

  els.severityChart.className = "severity-chart";
  els.severityChart.style.background = `conic-gradient(${slices.join(", ")})`;
  els.severityChart.innerHTML = `<span><strong>${total}</strong><small>Findings</small></span>`;
  els.severityBreakdown.className = "severity-breakdown";
  els.severityBreakdown.innerHTML = order
    .filter((severity) => bySeverity[severity])
    .map((severity) => `<span class="severity-chip ${severity}">${escapeHtml(severity)}: ${escapeHtml(bySeverity[severity])}</span>`)
    .join("");
}

function renderTrendChart(trend = []) {
  if (!trend.length) {
    els.riskTrend.className = "trend-chart empty";
    els.riskTrend.textContent = "No scan history yet.";
    return;
  }

  els.riskTrend.className = "trend-chart";
  els.riskTrend.innerHTML = trend.map((point) => {
    const height = Math.max(22, Math.round((point.riskScore / 100) * 180));
    return `<div class="trend-bar" style="height:${height}px"><span>${escapeHtml(new Date(point.scannedAt).toLocaleDateString())}</span></div>`;
  }).join("");
}
function renderActivityFeed() {
  if (!state.scans.length) {
    els.activityFeed.className = "activity-feed empty";
    els.activityFeed.textContent = "Recent activity will appear here.";
    return;
  }

  els.activityFeed.className = "activity-feed";
  els.activityFeed.innerHTML = state.scans.slice(0, 5).map((scan) => `
    <article class="activity-item">
      <strong>${escapeHtml(getHostname(scan))}</strong>
      <p class="muted-copy">${escapeHtml(scan.summary.total)} findings, risk ${escapeHtml(scan.risk.band)}, scanned ${escapeHtml(formatDate(scan.scannedAt))}</p>
    </article>
  `).join("");
}

function renderHistory() {
  els.totalScans.textContent = String(state.metrics.totalScans || state.scans.length);
  els.averageRisk.textContent = String(state.metrics.averageRisk || 0);
  renderTrendChart(state.metrics.riskTrend || []);
  renderActivityFeed();
  revealHistory(state.scans.length > 0 || state.hasRevealedResults);

  if (!state.scans.length) {
    els.historyList.className = "history-list empty";
    els.historyList.textContent = "No scans yet.";
    return;
  }

  els.historyList.className = "history-list";
  els.historyList.innerHTML = state.scans.map((scan) => {
    const active = state.activeScan?.id === scan.id ? " active" : "";
    return `
      <button class="history-item${active}" type="button" data-scan-id="${escapeHtml(scan.id)}">
        <div class="history-topline">
          <div>
            <strong>${escapeHtml(getHostname(scan))}</strong>
            <span class="history-meta">${escapeHtml(formatDate(scan.scannedAt))}</span>
          </div>
          <span class="severity-badge ${escapeHtml(scan.risk.band.toLowerCase())}">${escapeHtml(scan.risk.band)}</span>
        </div>
        <span class="history-meta">${escapeHtml(scan.summary.total)} findings across ${escapeHtml(scan.coverage.pagesCrawled)} page(s)</span>
        <span class="history-meta">Duration ${escapeHtml(formatDuration(scan.durationMs))}</span>
      </button>
    `;
  }).join("");
}

function renderSummary(scan) {
  if (!scan) {
    els.riskBand.textContent = "No data";
    els.riskBand.className = "pill muted";
    els.riskScore.textContent = "--";
    els.findingTotal.textContent = "--";
    els.pagesCrawled.textContent = "--";
    els.scanDuration.textContent = "--";
    els.topCategory.textContent = "--";
    renderSeverityChart({});
    return;
  }

  els.riskBand.textContent = scan.risk.band;
  els.riskBand.className = `pill ${scan.risk.band.toLowerCase()}`;
  els.riskScore.textContent = `${scan.risk.score}/100`;
  els.findingTotal.textContent = String(scan.summary.total);
  els.pagesCrawled.textContent = String(scan.coverage.pagesCrawled);
  els.scanDuration.textContent = formatDuration(scan.durationMs);
  els.topCategory.textContent = getTopCategory(scan);
  renderSeverityChart(scan.summary.bySeverity || {});
}

function renderReport(scan) {
  if (!scan) {
    els.reportContent.className = "report-content empty";
    els.reportContent.textContent = "Run a scan to generate a summary.";
    return;
  }

  const topFindings = scan.findings.slice(0, 6).map((finding) => `
    <tr>
      <td><span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(finding.title)}</td>
      <td>${escapeHtml(finding.confidence || "--")}%</td>
      <td>${escapeHtml(finding.location || "Global")}</td>
    </tr>
  `).join("");

  els.reportContent.className = "report-content";
  els.reportContent.innerHTML = `
    <article class="report-block">
      <h3>Executive summary</h3>
      <p>${escapeHtml(scan.report.executiveSummary)}</p>
    </article>
    <article class="report-block">
      <h3>Scan snapshot</h3>
      <table class="finding-table">
        <tbody>
          <tr><th>Target</th><td>${escapeHtml(scan.target)}</td></tr>
          <tr><th>Final URL</th><td>${escapeHtml(scan.finalUrl)}</td></tr>
          <tr><th>Scanned</th><td>${escapeHtml(formatDate(scan.scannedAt))}</td></tr>
          <tr><th>Duration</th><td>${escapeHtml(formatDuration(scan.durationMs))}</td></tr>
          <tr><th>Pages</th><td>${escapeHtml(scan.coverage.pagesCrawled)}</td></tr>
        </tbody>
      </table>
    </article>
    <article class="report-block">
      <h3>Top findings</h3>
      <table class="finding-table">
        <thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Affected</th></tr></thead>
        <tbody>${topFindings}</tbody>
      </table>
    </article>
  `;
}

function renderMemo(scan) {
  if (!scan) {
    els.aiContent.className = "memo-content empty";
    els.aiContent.textContent = "Compact remediation priorities will appear here for the selected scan.";
    return;
  }

  const actions = (scan.report.priorityActions || []).slice(0, 4).map((action) => `<li>${escapeHtml(action.action)}</li>`).join("");
  els.aiContent.className = "memo-content";
  els.aiContent.innerHTML = `
    <p>${escapeHtml(scan.aiAssist?.summary || scan.report.threatNarrative || scan.report.executiveSummary)}</p>
    <ol>${actions}</ol>
  `;
}

function renderCoverage(scan) {
  if (!scan) {
    els.coverageContent.className = "coverage-content empty";
    els.coverageContent.textContent = "No coverage data yet.";
    return;
  }

  els.coverageContent.className = "coverage-content";
  els.coverageContent.innerHTML = `
    <div class="inventory-grid">
      <article class="page-card"><h3>Forms</h3><p>${escapeHtml(scan.inventory.totalForms)}</p></article>
      <article class="page-card"><h3>Password surfaces</h3><p>${escapeHtml(scan.inventory.totalPasswordForms)}</p></article>
      <article class="page-card"><h3>Script hosts</h3><p>${escapeHtml(scan.inventory.externalScriptHosts.length)}</p></article>
    </div>
    <div class="pages-grid">
      ${scan.coverage.pages.map((page) => `
        <article class="page-card">
          <div class="page-topline">
            <h3>${escapeHtml(page.title)}</h3>
            <span class="meta-pill">HTTP ${escapeHtml(page.status)}</span>
          </div>
          <p class="page-url">${escapeHtml(page.url)}</p>
          <div class="page-stats">
            <span class="meta-pill">Forms ${escapeHtml(page.formsCount)}</span>
            <span class="meta-pill">Password ${escapeHtml(page.passwordForms)}</span>
            <span class="meta-pill">Inline scripts ${escapeHtml(page.inlineScriptCount)}</span>
            <span class="meta-pill">Links ${escapeHtml(page.internalLinks)}</span>
          </div>
        </article>
      `).join("")}
    </div>
  `;
}

function getFilteredFindings() {
  if (!state.activeScan) return [];
  return state.activeScan.findings.filter((finding) => {
    const severityMatch = state.filters.severity === "all" || finding.severity === state.filters.severity;
    const categoryMatch = state.filters.category === "all" || finding.category === state.filters.category;
    const query = state.filters.query.toLowerCase();
    const haystack = `${finding.title} ${finding.description} ${finding.evidence} ${finding.location || ""}`.toLowerCase();
    return severityMatch && categoryMatch && (!query || haystack.includes(query));
  });
}

function renderFindings() {
  if (!state.activeScan) {
    els.findingsList.className = "findings-list empty";
    els.findingsList.textContent = "No findings to display yet.";
    els.filterResults.textContent = "Showing 0 findings.";
    return;
  }

  const filtered = getFilteredFindings();
  els.filterResults.textContent = `Showing ${filtered.length} of ${state.activeScan.findings.length} findings.`;

  if (!filtered.length) {
    els.findingsList.className = "findings-list empty";
    els.findingsList.textContent = "No findings match the selected filters.";
    return;
  }

  els.findingsList.className = "findings-list";
  els.findingsList.innerHTML = filtered.map((finding) => `
    <article class="finding-card">
      <div class="finding-topline">
        <h3>${escapeHtml(finding.title)}</h3>
        <span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
      </div>
      <div class="finding-meta">
        <span class="meta-pill">${escapeHtml(finding.category)}</span>
        <span class="meta-pill">Confidence ${escapeHtml(finding.confidence || "--")}%</span>
        <span class="meta-pill">${escapeHtml(finding.location || "Global")}</span>
      </div>
      <div class="finding-sections">
        <p><strong>Description:</strong> ${escapeHtml(finding.description)}</p>
        <p><strong>Impact:</strong> ${escapeHtml(finding.impact)}</p>
        <p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
        <p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p>
      </div>
    </article>
  `).join("");
}

function renderCategoryFilter(scan) {
  const categories = scan ? Object.keys(scan.summary.byCategory || {}).sort() : [];
  els.categoryFilter.innerHTML = `
    <option value="all">All categories</option>
    ${categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join("")}
  `;
}

function updateDashboard(scan, { reveal = Boolean(scan) } = {}) {
  state.activeScan = scan;
  if (reveal) revealResults(Boolean(scan));
  renderSummary(scan);
  renderReport(scan);
  renderMemo(scan);
  renderCoverage(scan);
  renderCategoryFilter(scan);
  renderFindings();
  updateDownloadButtons(Boolean(scan));
  renderHistory();
}
async function loadHealth() {
  const payload = await fetchJson("/api/health");
  els.storageMode.textContent = payload.storageMode || "Storage";
}

async function loadAuthConfig() {
  const payload = await fetchJson("/api/auth/config");
  state.authConfig = payload;

  if (payload.googleEnabled && payload.googleClientId) {
    els.googleAuthWrapper.classList.remove("hidden");
    els.googleDisabledButton?.classList.add("hidden");
    initializeGoogleAuth(payload.googleClientId);
    return;
  }

  els.googleAuthWrapper.classList.remove("hidden");
  els.googleDisabledButton?.classList.remove("hidden");
  setAuthMessage("Google sign-in needs GOOGLE_CLIENT_ID in your environment settings.", "info");
}

async function loadScans() {
  const payload = await fetchJson("/api/scans");
  state.scans = payload.scans || [];
  state.metrics = payload.metrics || state.metrics;
  renderHistory();
}

async function loadScan(scanId, announce = true) {
  const scan = await fetchJson(`/api/scans/${encodeURIComponent(scanId)}`);
  updateDashboard(scan, { reveal: true });
  if (announce) {
    setStatus("success", `Loaded saved scan for ${scan.finalUrl}.`);
  }
}

function logout({ silent = false, message = "Signed out. Login to continue." } = {}) {
  setToken("");
  state.user = null;
  state.scans = [];
  state.activeScan = null;
  state.hasRevealedResults = false;
  state.metrics = { totalScans: 0, averageRisk: 0, riskTrend: [] };
  setAuthenticated(false);
  revealResults(false);
  revealHistory(false);
  updateDashboard(null, { reveal: false });
  if (!silent) setStatus("idle", message);
}

async function restoreSession() {
  if (!state.token) {
    setAuthenticated(false);
    revealResults(false);
    revealHistory(false);
    return;
  }

  try {
    const payload = await fetchJson("/api/auth/me");
    state.user = payload.user;
    els.userGreeting.textContent = `Welcome, ${payload.user.name}`;
    setAuthenticated(true);
    await Promise.all([loadHealth(), loadScans()]);
  } catch {
    logout({ silent: false, message: "Your session could not be restored. Please sign in again." });
  }
}

async function handleAuthSuccess(payload, message) {
  setToken(payload.token, "local");
  state.user = payload.user;
  els.userGreeting.textContent = `Welcome, ${payload.user.name}`;
  setAuthenticated(true);
  setAuthMessage(message, "success");
  await Promise.all([loadHealth(), loadScans()]);
  setStatus("success", "Workspace restored and ready.");
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
  if (!state.activeScan) return;
  const response = await fetch(`/api/reports/${encodeURIComponent(state.activeScan.id)}/${format}`, {
    headers: authHeaders(),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || "Unable to export report.");
  }
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") || "";
  const filename = disposition.match(/filename="(.+)"/)?.[1] || `sentinel-scan-report.${format}`;
  downloadBlob(blob, filename);
}

function buildHtmlSnapshot(scan) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8" /><title>Sentinel Scan Snapshot</title><style>body{font-family:Arial,sans-serif;margin:32px;color:#1f2933}h1,h2,h3{margin:0 0 10px}.card{border:1px solid #d9e1e8;border-radius:14px;padding:18px;margin-bottom:14px}</style></head><body><h1>Sentinel Scan Snapshot</h1><p><strong>Target:</strong> ${escapeHtml(scan.target)}</p><p><strong>Risk:</strong> ${escapeHtml(scan.risk.score)}/100 (${escapeHtml(scan.risk.band)})</p><p><strong>Scanned:</strong> ${escapeHtml(formatDate(scan.scannedAt))}</p><div class="card"><h2>Summary</h2><p>${escapeHtml(scan.report.executiveSummary)}</p></div>${scan.findings.slice(0,10).map((finding)=>`<div class="card"><h3>${escapeHtml(finding.title)}</h3><p><strong>Severity:</strong> ${escapeHtml(finding.severity)}</p><p><strong>Confidence:</strong> ${escapeHtml(finding.confidence || "--")}%</p><p><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p><p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p></div>`).join("")}</body></html>`;
}

function initializeGoogleAuth(clientId, attempt = 0) {
  if (!clientId || els.googleSigninButton.dataset.ready === "true") return;

  if (!window.google?.accounts?.id) {
    if (attempt < 25) {
      window.setTimeout(() => initializeGoogleAuth(clientId, attempt + 1), 200);
      return;
    }

    els.googleDisabledButton?.classList.remove("hidden");
    setAuthMessage("Google sign-in could not load. Check the Google Client ID and allowed origins.", "error");
    return;
  }

  els.googleDisabledButton?.classList.add("hidden");
  window.google.accounts.id.initialize({
    client_id: clientId,
    ux_mode: "popup",
    auto_select: false,
    cancel_on_tap_outside: true,
    callback: async ({ credential }) => {
      try {
        setAuthMessage("Verifying Google sign-in...", "info");
        const payload = await fetchJson("/api/auth/google", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ idToken: credential }),
        });
        await handleAuthSuccess(payload, "Google sign-in successful.");
      } catch (error) {
        setAuthMessage(error.message || "Google sign-in failed.", "error");
      }
    },
  });
  window.google.accounts.id.renderButton(els.googleSigninButton, {
    theme: document.body.dataset.theme === "dark" ? "filled_black" : "outline",
    size: "large",
    width: "320",
    text: "continue_with",
    shape: "pill",
  });
  els.googleSigninButton.dataset.ready = "true";
}

function openSupportModal() {
  els.supportModal.classList.remove("hidden");
  els.supportSuccess.classList.add("hidden");
  els.supportForm.classList.remove("hidden");
  els.supportForm.querySelector("input")?.focus();
}

function closeSupportModal() {
  els.supportModal.classList.add("hidden");
}

function sendSupportReport(event) {
  event.preventDefault();
  const formData = new FormData(els.supportForm);
  const name = String(formData.get("name") || "").trim();
  const email = String(formData.get("email") || "").trim();
  const message = String(formData.get("message") || "").trim();
  const subject = encodeURIComponent("Sentinel Scan Issue Report");
  const body = encodeURIComponent(`Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`);

  window.location.href = `mailto:${SUPPORT_EMAIL}?subject=${subject}&body=${body}`;
  els.supportForm.classList.add("hidden");
  els.supportSuccess.classList.remove("hidden");
  window.setTimeout(() => els.supportForm.reset(), 300);
}
els.showLogin.addEventListener("click", () => switchAuthMode("login"));
els.showSignup.addEventListener("click", () => switchAuthMode("signup"));
els.themeToggle.addEventListener("click", () => {
  setTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
});
els.logoutButton.addEventListener("click", () => logout());
els.supportButton.addEventListener("click", openSupportModal);
els.supportClose.addEventListener("click", closeSupportModal);
els.supportModal.addEventListener("click", (event) => {
  if (event.target === els.supportModal) closeSupportModal();
});
els.supportForm.addEventListener("submit", sendSupportReport);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.supportModal.classList.contains("hidden")) {
    closeSupportModal();
  }
});

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    setAuthMessage("Signing in...", "info");
    const payload = await fetchJson("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(els.loginForm))),
    });
    await handleAuthSuccess(payload, "Login successful.");
  } catch (error) {
    setAuthMessage(error.message || "Unable to login.", "error");
  }
});

els.signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    setAuthMessage("Creating account...", "info");
    const payload = await fetchJson("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(els.signupForm))),
    });
    await handleAuthSuccess(payload, "Account created successfully.");
  } catch (error) {
    setAuthMessage(error.message || "Unable to create account.", "error");
  }
});
els.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = String(new FormData(els.form).get("url") || "").trim();
  if (!url) {
    setStatus("error", "Enter a target URL before starting the scan.");
    return;
  }

  els.scanButton.disabled = true;
  revealResults(true);
  revealHistory(true);
  setLoadingSkeleton(true);
  setProgress(12);
  const progressMessages = [
    { percent: 26, text: "Validating target and starting passive scan." },
    { percent: 48, text: "Collecting transport and response posture." },
    { percent: 72, text: "Crawling same-origin pages and inventorying assets." },
    { percent: 88, text: "Scoring findings and preparing the report." },
  ];
  let step = 0;
  setStatus("loading", progressMessages[step].text);
  const progressTimer = setInterval(() => {
    step = Math.min(progressMessages.length - 1, step + 1);
    setProgress(progressMessages[step].percent);
    setStatus("loading", progressMessages[step].text);
  }, 1800);

  try {
    const payload = await fetchJson("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        options: {
          includeSubpages: els.includeSubpages.checked,
          maxPages: Number(els.maxPages.value),
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
    state.metrics.averageRisk = state.scans.length
      ? Math.round(state.scans.reduce((sum, scan) => sum + (scan.risk?.score || 0), 0) / state.scans.length)
      : 0;
    state.metrics.riskTrend = state.scans.slice(0, 10).map((scan) => ({
      scannedAt: scan.scannedAt,
      riskScore: scan.risk.score,
      findings: scan.summary.total,
    })).reverse();

    setProgress(100);
    updateDashboard(payload, { reveal: true });
    setStatus("success", `Scan complete for ${payload.finalUrl}.`);
  } catch (error) {
    setStatus("error", error.message || "Scan failed.");
    if (!state.activeScan) revealResults(false);
  } finally {
    clearInterval(progressTimer);
    window.setTimeout(() => setProgress(0), 900);
    setLoadingSkeleton(false);
    els.scanButton.disabled = false;
  }
});

els.historyList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-scan-id]");
  if (!button) return;
  try {
    revealResults(true);
    setStatus("loading", "Loading saved scan.");
    setLoadingSkeleton(true);
    setProgress(50);
    await loadScan(button.dataset.scanId);
    setProgress(100);
  } catch (error) {
    setStatus("error", error.message || "Unable to load the selected scan.");
  } finally {
    window.setTimeout(() => setProgress(0), 700);
    setLoadingSkeleton(false);
  }
});

els.severityFilter.addEventListener("change", () => {
  state.filters.severity = els.severityFilter.value;
  renderFindings();
});
els.categoryFilter.addEventListener("change", () => {
  state.filters.category = els.categoryFilter.value;
  renderFindings();
});
els.searchFilter.addEventListener("input", () => {
  state.filters.query = els.searchFilter.value.trim();
  renderFindings();
});

els.downloadPdf.addEventListener("click", () => downloadReport("pdf").catch((error) => setStatus("error", error.message)));
els.downloadTxt.addEventListener("click", () => downloadReport("txt").catch((error) => setStatus("error", error.message)));
els.downloadMd.addEventListener("click", () => downloadReport("md").catch((error) => setStatus("error", error.message)));
els.downloadJson.addEventListener("click", () => downloadReport("json").catch((error) => setStatus("error", error.message)));
els.downloadHtml.addEventListener("click", () => {
  if (!state.activeScan) return;
  downloadBlob(new Blob([buildHtmlSnapshot(state.activeScan)], { type: "text/html" }), "sentinel-scan-snapshot.html");
});

const savedTheme = localStorage.getItem("sentinelTheme");
if (savedTheme) setTheme(savedTheme);
els.statusSpinner.hidden = true;
setAuthenticated(false);
revealResults(false);
revealHistory(false);
updateDownloadButtons(false);
switchAuthMode("login");
renderSummary(null);
renderHistory();
renderReport(null);
renderMemo(null);
renderCoverage(null);
renderFindings();
setLoadingSkeleton(false);
setProgress(0);

Promise.all([loadAuthConfig(), restoreSession()]).catch(() => {
  setAuthenticated(false);
  revealResults(false);
  revealHistory(false);
});



