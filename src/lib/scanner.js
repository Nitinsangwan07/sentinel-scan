import tls from "node:tls";

const USER_AGENT =
  "SentinelScan/1.0 (+authorized-security-review; passive-checks-only)";

const DEFAULT_SCAN_OPTIONS = {
  includeSubpages: true,
  maxPages: 3,
  requestTimeoutMs: 12000,
};

const SECURITY_HEADERS = [
  {
    name: "content-security-policy",
    severity: "high",
    title: "Content Security Policy is missing",
    remediation:
      "Create a restrictive Content-Security-Policy that limits script, style, frame, and connection sources to trusted origins.",
  },
  {
    name: "x-frame-options",
    severity: "medium",
    title: "Clickjacking protection header is missing",
    remediation:
      "Set X-Frame-Options to DENY or SAMEORIGIN unless cross-origin framing is a deliberate requirement.",
  },
  {
    name: "x-content-type-options",
    severity: "medium",
    title: "MIME sniffing protection is missing",
    remediation: "Set X-Content-Type-Options to nosniff.",
  },
  {
    name: "referrer-policy",
    severity: "low",
    title: "Referrer policy is missing",
    remediation:
      "Set Referrer-Policy to a privacy-preserving value such as strict-origin-when-cross-origin.",
  },
  {
    name: "permissions-policy",
    severity: "low",
    title: "Permissions Policy is missing",
    remediation:
      "Add a Permissions-Policy header to explicitly disable browser features your application does not need.",
  },
];

const OUTDATED_JS_RULES = [
  { library: "jQuery", pattern: /jquery(?:\.min)?[-.]?(\d+\.\d+\.\d+)/i, safeMajor: 3, safeMinor: 6 },
  { library: "AngularJS", pattern: /angular(?:\.min)?[-.]?(\d+\.\d+\.\d+)/i, safeMajor: 1, safeMinor: 8 },
  { library: "Bootstrap", pattern: /bootstrap(?:\.bundle)?(?:\.min)?[-.]?(\d+\.\d+\.\d+)/i, safeMajor: 5, safeMinor: 3 },
];

const SENSITIVE_PATH_PATTERN = /(login|signin|admin|dashboard|account|portal|auth)/i;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

export function normalizeScanOptions(options = {}) {
  const includeSubpages = options.includeSubpages !== false;
  const requestedMaxPages = Number(options.maxPages);
  const maxPages = includeSubpages
    ? clamp(Number.isFinite(requestedMaxPages) ? requestedMaxPages : DEFAULT_SCAN_OPTIONS.maxPages, 2, 6)
    : 1;
  const requestTimeoutMs = clamp(
    Number.isFinite(Number(options.requestTimeoutMs))
      ? Number(options.requestTimeoutMs)
      : DEFAULT_SCAN_OPTIONS.requestTimeoutMs,
    4000,
    20000,
  );

  return {
    includeSubpages,
    maxPages,
    requestTimeoutMs,
  };
}

function severityWeight(severity) {
  return { critical: 10, high: 7, medium: 4, low: 2, info: 1 }[severity] || 0;
}

function buildFinding({
  id,
  title,
  severity,
  category,
  description,
  impact,
  remediation,
  evidence,
  location,
}) {
  return {
    id,
    title,
    severity,
    category,
    description,
    impact,
    remediation,
    evidence,
    location,
  };
}

async function fetchDocument(target, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || DEFAULT_SCAN_OPTIONS.requestTimeoutMs);

  try {
    const response = await fetch(target, {
      method: options.method || "GET",
      redirect: options.redirect || "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": USER_AGENT,
        Accept: options.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    const body = options.readBody === false ? "" : await response.text();

    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      url: response.url,
      body,
      contentType: response.headers.get("content-type") || "",
    };
  } finally {
    clearTimeout(timeout);
  }
}

function getHeaderMap(headers) {
  const values = {};

  for (const [key, value] of headers.entries()) {
    values[key.toLowerCase()] = value;
  }

  if (typeof headers.getSetCookie === "function") {
    values["set-cookie"] = headers.getSetCookie();
  }

  return values;
}

function parseCookies(rawCookies) {
  const cookieLines = Array.isArray(rawCookies)
    ? rawCookies
    : typeof rawCookies === "string" && rawCookies.length > 0
      ? rawCookies.split(/,(?=[^;]+?=)/)
      : [];

  return cookieLines.map((cookie) => {
    const parts = cookie.split(";").map((part) => part.trim());
    const [nameValue, ...attributes] = parts;
    const [name] = nameValue.split("=");
    const normalized = attributes.reduce((accumulator, attribute) => {
      const [attributeName, attributeValue] = attribute.split("=");
      accumulator[attributeName.toLowerCase()] = attributeValue || true;
      return accumulator;
    }, {});

    return {
      name,
      raw: cookie,
      secure: Boolean(normalized.secure),
      httpOnly: Boolean(normalized.httponly),
      sameSite: typeof normalized.samesite === "string" ? normalized.samesite : null,
    };
  });
}

function compareVersion(version, safeMajor, safeMinor) {
  const [major, minor] = version.split(".").map((value) => Number(value || 0));

  if (Number.isNaN(major) || Number.isNaN(minor)) {
    return false;
  }

  if (major < safeMajor) {
    return true;
  }

  return major === safeMajor && minor < safeMinor;
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function parseTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim() : "Untitled page";
}

function extractInternalLinks(html, baseUrl, origin) {
  const hrefRegex = /<a\b[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  const discovered = [];
  let match = hrefRegex.exec(html);

  while (match) {
    try {
      const candidate = new URL(match[1], baseUrl);

      if (
        ["http:", "https:"].includes(candidate.protocol) &&
        candidate.origin === origin
      ) {
        candidate.hash = "";
        discovered.push(candidate.toString());
      }
    } catch {
      // Ignore malformed links.
    }

    match = hrefRegex.exec(html);
  }

  return unique(discovered);
}

function extractExternalScriptHosts(html, baseUrl) {
  const srcRegex = /<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi;
  const base = new URL(baseUrl);
  const hosts = [];
  let match = srcRegex.exec(html);

  while (match) {
    try {
      const candidate = new URL(match[1], baseUrl);

      if (candidate.origin !== base.origin) {
        hosts.push(candidate.hostname);
      }
    } catch {
      // Ignore malformed src values.
    }

    match = srcRegex.exec(html);
  }

  return unique(hosts);
}

function summarizePage(html, responseInfo, pageUrl, origin) {
  const formsCount = (html.match(/<form[\s>]/gi) || []).length;
  const passwordForms = (html.match(/<input[^>]*type=["']password["']/gi) || []).length;
  const inlineScriptCount = (html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi) || []).length;
  const externalScriptHosts = extractExternalScriptHosts(html, pageUrl);
  const internalLinks = extractInternalLinks(html, pageUrl, origin);

  return {
    url: pageUrl,
    title: parseTitle(html),
    status: responseInfo.status,
    contentType: responseInfo.contentType,
    formsCount,
    passwordForms,
    inlineScriptCount,
    externalScriptHosts,
    internalLinks: internalLinks.length,
    loginSignal: SENSITIVE_PATH_PATTERN.test(new URL(pageUrl).pathname),
  };
}

function analyzeHeaders(target, responseInfo) {
  const findings = [];
  const headers = getHeaderMap(responseInfo.headers);
  const parsedTarget = new URL(responseInfo.url || target);
  const location = responseInfo.url;

  for (const header of SECURITY_HEADERS) {
    if (!headers[header.name]) {
      findings.push(
        buildFinding({
          id: `missing-${header.name}`,
          title: header.title,
          severity: header.severity,
          category: "headers",
          description: `${header.name} was not present in the HTTP response.`,
          impact:
            "Browsers may be missing a layer of client-side hardening, increasing exposure to common web attacks.",
          remediation: header.remediation,
          evidence: `Response URL: ${responseInfo.url}`,
          location,
        }),
      );
    }
  }

  if (headers.server || headers["x-powered-by"]) {
    findings.push(
      buildFinding({
        id: "banner-leakage",
        title: "Technology banner leakage detected",
        severity: "low",
        category: "headers",
        description:
          "The response includes identifying server or framework headers that can help attackers fingerprint the stack.",
        impact:
          "Version or platform disclosure can make targeted exploitation and recon easier for an attacker.",
        remediation:
          "Suppress non-essential banner headers or standardize them at the edge proxy or application gateway.",
        evidence: `Server: ${headers.server || "n/a"} | X-Powered-By: ${headers["x-powered-by"] || "n/a"}`,
        location,
      }),
    );
  }

  if (parsedTarget.protocol === "https:" && !headers["strict-transport-security"]) {
    findings.push(
      buildFinding({
        id: "https-without-hsts",
        title: "HTTPS is enabled without HSTS",
        severity: "high",
        category: "transport",
        description: "The application serves over HTTPS but does not instruct browsers to stick to HTTPS.",
        impact:
          "Users may remain vulnerable to downgrade and SSL stripping attacks during first contact or mixed navigation flows.",
        remediation:
          "Deploy Strict-Transport-Security only after HTTPS coverage is validated across the full application surface.",
        evidence: `Final URL: ${responseInfo.url}`,
        location,
      }),
    );
  }

  if (headers["strict-transport-security"]) {
    const maxAgeMatch = headers["strict-transport-security"].match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;

    if (maxAge > 0 && maxAge < 15552000) {
      findings.push(
        buildFinding({
          id: "weak-hsts-duration",
          title: "HSTS max-age is shorter than common production baselines",
          severity: "medium",
          category: "transport",
          description:
            "The HSTS header is present, but the advertised lifetime is shorter than a common six-month baseline.",
          impact:
            "A short HSTS duration weakens the browser's ability to remember and enforce secure transport over time.",
          remediation: "Increase HSTS max-age after verifying that the full site is HTTPS-ready.",
          evidence: headers["strict-transport-security"],
          location,
        }),
      );
    }
  }

  if (headers["content-security-policy"] && /unsafe-inline|\s\*/i.test(headers["content-security-policy"])) {
    findings.push(
      buildFinding({
        id: "permissive-csp",
        title: "Content Security Policy appears permissive",
        severity: "medium",
        category: "headers",
        description:
          "The CSP includes wildcard or inline script allowances that can reduce its protective value.",
        impact:
          "A broad CSP may fail to meaningfully contain cross-site scripting or untrusted resource loading.",
        remediation:
          "Tighten the CSP by reducing wildcard sources and removing unsafe-inline where possible.",
        evidence: headers["content-security-policy"],
        location,
      }),
    );
  }

  if (headers["access-control-allow-origin"] === "*") {
    findings.push(
      buildFinding({
        id: "wildcard-cors",
        title: "Wildcard CORS policy observed",
        severity: headers["access-control-allow-credentials"] === "true" ? "high" : "medium",
        category: "headers",
        description:
          "The response allows any origin via Access-Control-Allow-Origin, which can expand data exposure in browser contexts.",
        impact:
          "Cross-origin integrations may receive broader access than intended, especially when APIs return sensitive data.",
        remediation:
          "Replace wildcard origins with an explicit allowlist for trusted front-end origins and review credential handling.",
        evidence: `Access-Control-Allow-Origin: *`,
        location,
      }),
    );
  }

  return { findings, headers };
}

function analyzeCookies(cookieInfo, pageUrl) {
  const findings = [];

  for (const cookie of cookieInfo) {
    if (!cookie.secure) {
      findings.push(
        buildFinding({
          id: `cookie-secure-${cookie.name}`,
          title: `Cookie ${cookie.name} is missing the Secure flag`,
          severity: "high",
          category: "cookies",
          description: "A session or state cookie can be transmitted over an unencrypted channel if the browser allows it.",
          impact: "Sensitive identifiers may be exposed through interception or downgrade scenarios.",
          remediation: "Set the Secure attribute on cookies that should only travel over HTTPS.",
          evidence: cookie.raw,
          location: pageUrl,
        }),
      );
    }

    if (!cookie.httpOnly) {
      findings.push(
        buildFinding({
          id: `cookie-httponly-${cookie.name}`,
          title: `Cookie ${cookie.name} is missing the HttpOnly flag`,
          severity: "medium",
          category: "cookies",
          description: "The cookie may be readable from client-side JavaScript.",
          impact: "Cross-site scripting could expose session identifiers or sensitive state values.",
          remediation: "Set HttpOnly on cookies that do not need to be accessed by front-end JavaScript.",
          evidence: cookie.raw,
          location: pageUrl,
        }),
      );
    }

    if (!cookie.sameSite) {
      findings.push(
        buildFinding({
          id: `cookie-samesite-${cookie.name}`,
          title: `Cookie ${cookie.name} is missing SameSite`,
          severity: "medium",
          category: "cookies",
          description: "No SameSite attribute was detected on the cookie.",
          impact: "Cross-site request scenarios become easier to abuse, especially around authenticated actions.",
          remediation:
            "Set SameSite=Lax or SameSite=Strict for session cookies unless a cross-site flow explicitly requires None.",
          evidence: cookie.raw,
          location: pageUrl,
        }),
      );
    }
  }

  return findings;
}

function analyzeHtml(html, pageUrl) {
  const findings = [];
  const technologies = [];
  const title = parseTitle(html);
  const lowerHtml = html.toLowerCase();
  const formsCount = (html.match(/<form[\s>]/gi) || []).length;
  const hasPasswordField = /<input[^>]*type=["']password["']/i.test(html);
  const hasCsrfHint = /(csrf|xsrf|authenticity_token)/i.test(html);
  const inlineScriptCount = (html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi) || []).length;
  const targetBlankWithoutRel =
    (html.match(/<a\b(?=[^>]*target=["']_blank["'])(?![^>]*rel=["'][^"']*(noopener|noreferrer)[^"']*["'])[^>]*>/gi) || [])
      .length;
  const scriptHosts = extractExternalScriptHosts(html, pageUrl);

  if (!html) {
    findings.push(
      buildFinding({
        id: "empty-body",
        title: "No HTML content retrieved for analysis",
        severity: "info",
        category: "content",
        description: "The scanner received little or no HTML body content from the target page.",
        impact: "Content-focused checks such as form analysis may be incomplete.",
        remediation:
          "Confirm the application is reachable without authentication for this scan or expand the scanner with authenticated checks.",
        evidence: `Final URL: ${pageUrl}`,
        location: pageUrl,
      }),
    );

    return { findings, technologies, pageSignals: { scriptHosts } };
  }

  if (/index of\s*\//i.test(title)) {
    findings.push(
      buildFinding({
        id: `directory-listing-${pageUrl}`,
        title: "Directory listing pattern detected",
        severity: "medium",
        category: "content",
        description:
          "The page title resembles an auto-generated directory index, which can reveal files and folders that were not meant for browsing.",
        impact:
          "Directory indexing can expose sensitive files, backup artifacts, or internal structure to unauthenticated visitors.",
        remediation:
          "Disable directory indexing at the web server or application layer and explicitly publish only intended assets.",
        evidence: `Page title: ${title}`,
        location: pageUrl,
      }),
    );
  }

  if (formsCount > 0) {
    if (hasPasswordField && pageUrl.startsWith("http://")) {
      findings.push(
        buildFinding({
          id: `password-over-http-${pageUrl}`,
          title: "Password form served over HTTP",
          severity: "critical",
          category: "forms",
          description: "A password field appears on a page that is not protected by HTTPS.",
          impact: "Credentials can be intercepted or altered in transit.",
          remediation: "Serve authentication workflows only over HTTPS and redirect all HTTP traffic to HTTPS.",
          evidence: `Form URL: ${pageUrl}`,
          location: pageUrl,
        }),
      );
    }

    if (!hasCsrfHint) {
      findings.push(
        buildFinding({
          id: `csrf-token-not-observed-${pageUrl}`,
          title: "No obvious CSRF token markers found in forms",
          severity: "medium",
          category: "forms",
          description:
            "The HTML did not include common token names often used to protect state-changing form submissions.",
          impact:
            "If the application relies on cookies for session state, cross-site request forgery risks may be higher.",
          remediation:
            "Review state-changing forms and ensure CSRF protections are consistently enforced server-side.",
          evidence: `Searched for token markers on ${pageUrl}.`,
          location: pageUrl,
        }),
      );
    }

    const insecureActionMatch = html.match(/<form\b[^>]*action=["'](http:\/\/[^"']+)["']/i);

    if (pageUrl.startsWith("https://") && insecureActionMatch?.[1]) {
      findings.push(
        buildFinding({
          id: `insecure-form-action-${pageUrl}`,
          title: "HTTPS page submits a form to HTTP",
          severity: "high",
          category: "forms",
          description:
            "A form action appears to send data to an insecure HTTP destination even though the current page is HTTPS.",
          impact: "Sensitive values entered into the form may be downgraded onto an unencrypted request.",
          remediation: "Update form targets so state-changing or sensitive submissions always use HTTPS endpoints.",
          evidence: insecureActionMatch[1],
          location: pageUrl,
        }),
      );
    }
  }

  if (inlineScriptCount >= 5) {
    findings.push(
      buildFinding({
        id: `heavy-inline-script-usage-${pageUrl}`,
        title: "Heavy inline script usage detected",
        severity: "low",
        category: "content",
        description: "A large number of inline scripts often makes CSP adoption and XSS hardening more difficult.",
        impact: "Inline JavaScript expands the blast radius of cross-site scripting weaknesses.",
        remediation:
          "Move scripts into versioned external assets and use nonce- or hash-based CSP rules where inline code is unavoidable.",
        evidence: `Inline script blocks observed: ${inlineScriptCount}`,
        location: pageUrl,
      }),
    );
  }

  if (pageUrl.startsWith("https://") && /(?:src|href|action)=["']http:\/\//i.test(html)) {
    findings.push(
      buildFinding({
        id: `mixed-content-reference-${pageUrl}`,
        title: "Potential mixed-content references detected",
        severity: "medium",
        category: "content",
        description: "The page source references absolute HTTP resources while the page itself is served over HTTPS.",
        impact: "Browsers may block insecure resources or users may experience content integrity issues.",
        remediation:
          "Replace hard-coded HTTP references with HTTPS URLs or protocol-relative/internal secure asset paths.",
        evidence: `Page source contained one or more http:// references.`,
        location: pageUrl,
      }),
    );
  }

  if (targetBlankWithoutRel > 0) {
    findings.push(
      buildFinding({
        id: `blank-link-noopener-${pageUrl}`,
        title: "Links open a new tab without rel protections",
        severity: "low",
        category: "content",
        description:
          "One or more links use target=_blank without rel=noopener or rel=noreferrer, which can expose the opener window.",
        impact: "A newly opened page may be able to manipulate the originating tab in some browser contexts.",
        remediation: "Add rel=noopener or rel=noreferrer to links that open untrusted destinations in a new tab.",
        evidence: `Affected anchors detected: ${targetBlankWithoutRel}`,
        location: pageUrl,
      }),
    );
  }

  for (const rule of OUTDATED_JS_RULES) {
    const match = html.match(rule.pattern);

    if (match?.[1]) {
      technologies.push(`${rule.library} ${match[1]}`);

      if (compareVersion(match[1], rule.safeMajor, rule.safeMinor)) {
        findings.push(
          buildFinding({
            id: `outdated-${rule.library.toLowerCase()}-${pageUrl}`,
            title: `${rule.library} appears outdated`,
            severity: "medium",
            category: "dependencies",
            description: `The application references ${rule.library} ${match[1]}, which may be behind current secure maintenance baselines.`,
            impact:
              "Older client-side libraries can carry known vulnerabilities or make exploit development easier.",
            remediation:
              "Validate the detected version and upgrade to a currently supported release after regression testing.",
            evidence: `Detected script reference: ${match[0]}`,
            location: pageUrl,
          }),
        );
      }
    }
  }

  if (/<meta[^>]*generator/i.test(lowerHtml)) {
    findings.push(
      buildFinding({
        id: `generator-meta-exposed-${pageUrl}`,
        title: "Generator metadata exposed",
        severity: "low",
        category: "content",
        description: "A generator meta tag can reveal the CMS or platform in use.",
        impact: "Platform disclosure helps with targeted recon against known product weaknesses.",
        remediation: "Remove or standardize generator metadata in production templates where possible.",
        evidence: "A generator meta tag was found in the HTML source.",
        location: pageUrl,
      }),
    );
  }

  if (SENSITIVE_PATH_PATTERN.test(new URL(pageUrl).pathname) && pageUrl.startsWith("http://")) {
    findings.push(
      buildFinding({
        id: `sensitive-path-over-http-${pageUrl}`,
        title: "Sensitive-looking page is served over HTTP",
        severity: "high",
        category: "transport",
        description:
          "The URL path suggests a login, admin, or account-related page, but the page itself is not protected by HTTPS.",
        impact: "Administrative workflows or user account actions may be exposed to interception or tampering.",
        remediation: "Enforce HTTPS everywhere and especially on login, account, and administrative paths.",
        evidence: pageUrl,
        location: pageUrl,
      }),
    );
  }

  return {
    findings,
    technologies,
    pageSignals: {
      scriptHosts,
      formsCount,
      passwordForms: hasPasswordField ? 1 : 0,
      loginSignal: SENSITIVE_PATH_PATTERN.test(new URL(pageUrl).pathname),
    },
  };
}

async function fetchOptionalFile(target, filePath, timeoutMs) {
  const url = new URL(filePath, target).toString();

  try {
    const response = await fetchDocument(url, { timeoutMs, readBody: false });
    return { path: filePath, status: response.status, url: response.url };
  } catch {
    return { path: filePath, status: 0, url };
  }
}

async function inspectHttpRedirect(target, timeoutMs) {
  const secureUrl = new URL(target);

  if (secureUrl.protocol !== "https:") {
    return null;
  }

  const insecureUrl = new URL(target);
  insecureUrl.protocol = "http:";

  try {
    const response = await fetchDocument(insecureUrl, {
      method: "GET",
      redirect: "manual",
      timeoutMs,
      readBody: false,
    });

    return {
      from: insecureUrl.toString(),
      status: response.status,
      location: response.headers.get("location"),
    };
  } catch (error) {
    return {
      from: insecureUrl.toString(),
      status: 0,
      error: error.message,
    };
  }
}

function analyzeAuxiliaryFiles(auxiliaryFiles) {
  const findings = [];
  const securityTxt = auxiliaryFiles.find((file) => file.path === "/.well-known/security.txt");
  const robots = auxiliaryFiles.find((file) => file.path === "/robots.txt");
  const sitemap = auxiliaryFiles.find((file) => file.path === "/sitemap.xml");

  if (!securityTxt || securityTxt.status >= 400 || securityTxt.status === 0) {
    findings.push(
      buildFinding({
        id: "security-txt-missing",
        title: "security.txt not found",
        severity: "info",
        category: "governance",
        description:
          "The standard /.well-known/security.txt contact file was not detected during this passive review.",
        impact:
          "External researchers and internal testers may have a less clear route for reporting vulnerabilities responsibly.",
        remediation:
          "Publish a security.txt file with a monitored disclosure contact, policy, and encryption metadata where appropriate.",
        evidence: `Checked /.well-known/security.txt -> status ${securityTxt?.status || "unreachable"}`,
        location: securityTxt?.url || new URL("/.well-known/security.txt", auxiliaryFiles[0]?.url || "http://localhost/").toString(),
      }),
    );
  }

  if (robots && robots.status === 200) {
    findings.push(
      buildFinding({
        id: "robots-exposed",
        title: "robots.txt is publicly accessible",
        severity: "info",
        category: "recon",
        description:
          "This is normal for most websites, but the file can sometimes reveal administrative or sensitive route patterns worth reviewing.",
        impact: "Route disclosures in robots.txt can provide a roadmap for manual follow-up validation.",
        remediation:
          "Review robots.txt entries and remove any references that unnecessarily expose internal or high-value paths.",
        evidence: `robots.txt responded with HTTP ${robots.status}`,
        location: robots.url,
      }),
    );
  }

  if (!sitemap || sitemap.status >= 400 || sitemap.status === 0) {
    findings.push(
      buildFinding({
        id: "sitemap-not-found",
        title: "sitemap.xml not found",
        severity: "info",
        category: "coverage",
        description:
          "A sitemap was not detected, which can make broad passive discovery harder for both defenders and search engines.",
        impact: "The scan may have a smaller picture of the site's public structure when link discovery is limited.",
        remediation:
          "Consider publishing a current sitemap.xml to improve discoverability and easier defensive inventorying.",
        evidence: `Checked /sitemap.xml -> status ${sitemap?.status || "unreachable"}`,
        location: sitemap?.url || null,
      }),
    );
  }

  return findings;
}

function inspectTlsCertificate(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 7000,
      },
      () => {
        const certificate = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();

        socket.end();

        resolve({
          supported: true,
          protocol,
          cipher: cipher?.name || "unknown",
          validFrom: certificate?.valid_from || null,
          validTo: certificate?.valid_to || null,
          issuer: certificate?.issuer?.O || certificate?.issuer?.CN || "unknown",
          subject: certificate?.subject?.CN || hostname,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
        });
      },
    );

    socket.on("error", (error) => {
      resolve({
        supported: false,
        error: error.message,
      });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        supported: false,
        error: "TLS handshake timed out.",
      });
    });
  });
}

function analyzeTls(tlsInfo) {
  const findings = [];

  if (!tlsInfo || tlsInfo.supported === null) {
    return findings;
  }

  if (!tlsInfo.supported) {
    findings.push(
      buildFinding({
        id: "tls-handshake-failed",
        title: "TLS inspection could not be completed",
        severity: "high",
        category: "transport",
        description: "The platform could not complete a TLS handshake or inspect the presented certificate.",
        impact: "Certificate validity and protocol configuration may need manual review.",
        remediation:
          "Verify TLS availability, certificate chain health, and network reachability from the scanning environment.",
        evidence: tlsInfo.error || "Unknown TLS inspection failure.",
        location: null,
      }),
    );

    return findings;
  }

  if (tlsInfo.authorizationError) {
    findings.push(
      buildFinding({
        id: "tls-authorization-error",
        title: "Certificate trust issue detected",
        severity: "high",
        category: "transport",
        description: "Node reported a certificate authorization problem during the handshake.",
        impact: "Browsers or clients may reject the connection or warn users about authenticity issues.",
        remediation:
          "Inspect the certificate chain, hostname coverage, and intermediate CA configuration for trust problems.",
        evidence: tlsInfo.authorizationError,
        location: null,
      }),
    );
  }

  const protocol = String(tlsInfo.protocol || "");

  if (/TLSv1(\.0|\.1)?/i.test(protocol)) {
    findings.push(
      buildFinding({
        id: "legacy-tls-protocol",
        title: "Legacy TLS protocol observed",
        severity: "high",
        category: "transport",
        description: `The endpoint negotiated ${protocol}, which is below modern transport expectations.`,
        impact: "Older TLS versions increase exposure to deprecated ciphers and protocol downgrade risk.",
        remediation: "Disable TLS 1.0 and 1.1, then prefer TLS 1.2+ with modern cipher suites.",
        evidence: `Negotiated protocol: ${protocol}`,
        location: null,
      }),
    );
  }

  if (tlsInfo.validTo) {
    const expiry = new Date(tlsInfo.validTo);
    const daysRemaining = Math.round((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

    if (daysRemaining <= 14) {
      findings.push(
        buildFinding({
          id: "certificate-expiring-soon",
          title: "TLS certificate expires soon",
          severity: daysRemaining <= 0 ? "critical" : "medium",
          category: "transport",
          description: `The certificate has ${daysRemaining} day(s) remaining before expiry.`,
          impact: "Impending or expired certificates can cause service disruption and browser trust failures.",
          remediation: "Renew the certificate and validate automatic renewal coverage before the expiry date.",
          evidence: `Certificate expiry: ${tlsInfo.validTo}`,
          location: null,
        }),
      );
    }
  }

  return findings;
}

function analyzeRedirectPolicy(target, finalUrl, redirectInfo) {
  const findings = [];
  const submittedUrl = new URL(target);

  if (submittedUrl.protocol === "http:" && !finalUrl.startsWith("https://")) {
    findings.push(
      buildFinding({
        id: "http-without-https-upgrade",
        title: "HTTP target did not upgrade to HTTPS",
        severity: "critical",
        category: "transport",
        description: "The target was submitted over HTTP and did not end on an HTTPS destination.",
        impact: "Traffic remains exposed to interception and tampering in transit.",
        remediation: "Enable HTTPS across the site and enforce a permanent redirect from HTTP to HTTPS.",
        evidence: `Submitted target: ${target} | Final URL: ${finalUrl}`,
        location: finalUrl,
      }),
    );
  }

  if (redirectInfo && redirectInfo.status && redirectInfo.status < 300) {
    findings.push(
      buildFinding({
        id: "http-available-without-redirect",
        title: "HTTP endpoint is reachable without redirecting",
        severity: "high",
        category: "transport",
        description: "The HTTP version of the site responded successfully without forcing a redirect to HTTPS.",
        impact: "Users may access an insecure version of the application, weakening confidentiality and integrity guarantees.",
        remediation: "Return a permanent redirect from HTTP to the canonical HTTPS origin.",
        evidence: `HTTP probe ${redirectInfo.from} returned status ${redirectInfo.status}`,
        location: redirectInfo.from,
      }),
    );
  }

  if (redirectInfo?.status >= 300 && redirectInfo.status < 400 && redirectInfo.location) {
    const location = new URL(redirectInfo.location, redirectInfo.from);

    if (location.protocol !== "https:") {
      findings.push(
        buildFinding({
          id: "http-redirects-to-insecure-destination",
          title: "HTTP redirect does not upgrade to HTTPS",
          severity: "high",
          category: "transport",
          description: "The insecure endpoint redirects somewhere other than an HTTPS destination.",
          impact: "Users may still land on an insecure route during navigation.",
          remediation: "Ensure the initial redirect target uses HTTPS and ideally the canonical host.",
          evidence: `HTTP redirect location: ${location.toString()}`,
          location: redirectInfo.from,
        }),
      );
    }
  }

  return findings;
}

async function crawlSite(primaryResponse, options) {
  const origin = new URL(primaryResponse.url).origin;
  const pages = [];
  const findings = [];
  const technologies = [];
  const queue = [];
  const visited = new Set();
  const inventory = {
    totalForms: 0,
    totalPasswordForms: 0,
    loginPages: [],
    externalScriptHosts: [],
  };

  async function processPage(pageUrl, existingResponse = null) {
    if (visited.has(pageUrl) || pages.length >= options.maxPages) {
      return;
    }

    visited.add(pageUrl);

    let responseInfo;

    try {
      responseInfo = existingResponse || (await fetchDocument(pageUrl, { timeoutMs: options.requestTimeoutMs }));
    } catch (error) {
      findings.push(
        buildFinding({
          id: `page-fetch-failed-${pageUrl}`,
          title: "Page could not be retrieved during crawl",
          severity: "info",
          category: "coverage",
          description: "The crawler could not retrieve one of the queued same-origin pages.",
          impact: "Coverage is incomplete for this target, so some page-level observations may be missing.",
          remediation: "Review whether the page blocks automated requests or requires authentication.",
          evidence: `${pageUrl} -> ${error.message}`,
          location: pageUrl,
        }),
      );
      return;
    }

    const contentType = String(responseInfo.contentType || "").toLowerCase();
    const html =
      contentType.includes("text/html") || contentType.includes("application/xhtml+xml") || !contentType
        ? responseInfo.body
        : "";
    const pageSummary = summarizePage(html, responseInfo, responseInfo.url, origin);
    const analysis = analyzeHtml(html, responseInfo.url);

    pageSummary.findingsCount = analysis.findings.length;
    pages.push(pageSummary);
    findings.push(...analysis.findings);
    technologies.push(...analysis.technologies);
    inventory.totalForms += analysis.pageSignals.formsCount || 0;
    inventory.totalPasswordForms += analysis.pageSignals.passwordForms || 0;
    inventory.externalScriptHosts.push(...analysis.pageSignals.scriptHosts);

    if (pageSummary.loginSignal) {
      inventory.loginPages.push(responseInfo.url);
    }

    if (options.includeSubpages && pages.length < options.maxPages && html) {
      for (const link of extractInternalLinks(html, responseInfo.url, origin)) {
        if (!visited.has(link) && !queue.includes(link)) {
          queue.push(link);
        }
      }
    }
  }

  await processPage(primaryResponse.url, primaryResponse);

  while (queue.length > 0 && pages.length < options.maxPages) {
    const nextUrl = queue.shift();
    await processPage(nextUrl);
  }

  inventory.externalScriptHosts = unique(inventory.externalScriptHosts).sort();
  inventory.loginPages = unique(inventory.loginPages);

  return {
    pages,
    findings,
    technologies: unique(technologies),
    inventory,
  };
}

function calculateRiskScore(findings) {
  const rawScore = findings.reduce((total, finding) => total + severityWeight(finding.severity), 0);
  return Math.min(100, rawScore);
}

function scoreBand(score) {
  if (score >= 70) return "Critical";
  if (score >= 45) return "High";
  if (score >= 20) return "Moderate";
  return "Low";
}

function groupFindings(findings) {
  return findings.reduce(
    (summary, finding) => {
      summary.total += 1;
      summary.bySeverity[finding.severity] = (summary.bySeverity[finding.severity] || 0) + 1;
      summary.byCategory[finding.category] = (summary.byCategory[finding.category] || 0) + 1;
      return summary;
    },
    {
      total: 0,
      bySeverity: {},
      byCategory: {},
    },
  );
}

function buildNarrative(scan) {
  const topFindings = [...scan.findings]
    .sort((left, right) => severityWeight(right.severity) - severityWeight(left.severity))
    .slice(0, 5);

  const quickWins = scan.findings
    .filter((finding) => ["headers", "cookies"].includes(finding.category))
    .slice(0, 3)
    .map((finding) => finding.remediation);

  const priorityActions = topFindings.map((finding, index) => ({
    priority: index + 1,
    action: finding.remediation,
    reason: `${finding.title} (${finding.severity})`,
  }));

  const executiveSummary =
    topFindings.length === 0
      ? "No material weaknesses were detected by this passive review, although authenticated testing and deeper validation are still recommended."
      : `The scan covered ${scan.coverage.pages.length} page(s) and identified ${scan.summary.total} finding(s). The highest-priority work should focus on the ${topFindings
          .slice(0, 3)
          .map((finding) => finding.category)
          .filter((value, index, array) => array.indexOf(value) === index)
          .join(", ")} controls that reduce exposure across the whole application.`;

  const threatNarrative =
    topFindings.length === 0
      ? "No obvious exploit chain stood out from the passive checks that were run."
      : `An attacker performing initial reconnaissance could use the observed weaknesses to fingerprint the stack, inspect login and content flows, and focus on the parts of the site with weaker transport, browser hardening, or dependency hygiene. The current scan stays passive and should be followed with manual validation where risk is highest.`;

  const attackSurface = `The crawl observed ${scan.coverage.pages.length} page(s), ${scan.inventory.totalForms} form(s), ${scan.inventory.totalPasswordForms} password-entry surface(s), and ${scan.inventory.externalScriptHosts.length} third-party script host(s).`;
  const coverageNotes = scan.options.includeSubpages
    ? `Same-origin crawl was enabled with a limit of ${scan.options.maxPages} page(s).`
    : "Only the submitted entry page was inspected because same-origin crawling was disabled.";

  return {
    executiveSummary,
    threatNarrative,
    attackSurface,
    coverageNotes,
    priorityActions,
    quickWins,
  };
}

function buildMarkdownReport(scan) {
  const lines = [
    `# Sentinel Scan Report`,
    ``,
    `- Target: ${scan.target}`,
    `- Final URL: ${scan.finalUrl}`,
    `- Scanned at: ${scan.scannedAt}`,
    `- Risk score: ${scan.risk.score}/100 (${scan.risk.band})`,
    `- Findings: ${scan.summary.total}`,
    `- Pages crawled: ${scan.coverage.pages.length}`,
    ``,
    `## Executive Summary`,
    ``,
    scan.report.executiveSummary,
    ``,
    `## Threat Narrative`,
    ``,
    scan.report.threatNarrative,
    ``,
    `## Attack Surface`,
    ``,
    scan.report.attackSurface,
    ``,
    `## Priority Actions`,
    ``,
  ];

  for (const action of scan.report.priorityActions) {
    lines.push(`${action.priority}. ${action.action} (${action.reason})`);
  }

  lines.push(``, `## Coverage`, ``);
  lines.push(`- ${scan.report.coverageNotes}`);
  lines.push(`- Login-like pages observed: ${scan.inventory.loginPages.length}`);
  lines.push(`- External script hosts: ${scan.inventory.externalScriptHosts.join(", ") || "None detected"}`);
  lines.push(``);
  lines.push(`## Pages`, ``);

  for (const page of scan.coverage.pages) {
    lines.push(`- ${page.url} | status ${page.status} | forms ${page.formsCount} | findings ${page.findingsCount}`);
  }

  lines.push(``, `## Findings`, ``);

  for (const finding of scan.findings) {
    lines.push(`### ${finding.title}`);
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- Location: ${finding.location || "n/a"}`);
    lines.push(`- Description: ${finding.description}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Remediation: ${finding.remediation}`);
    lines.push(`- Evidence: ${finding.evidence}`);
    lines.push(``);
  }

  lines.push(`## Scope Notes`, ``);
  lines.push(
    "This platform performs passive, low-impact checks intended for authorized security reviews. It does not exploit vulnerabilities, brute force content, or perform intrusive testing.",
  );

  return lines.join("\n");
}

export async function scanWebsite(target, requestedOptions = {}) {
  const options = normalizeScanOptions(requestedOptions);
  const primaryResponse = await fetchDocument(target, { timeoutMs: options.requestTimeoutMs });
  const finalUrl = primaryResponse.url;
  const headerAnalysis = analyzeHeaders(target, primaryResponse);
  const cookieInfo = parseCookies(headerAnalysis.headers["set-cookie"]);
  const crawl = await crawlSite(primaryResponse, options);
  const redirectInfo = await inspectHttpRedirect(finalUrl, options.requestTimeoutMs);
  const auxiliaryFiles = await Promise.all([
    fetchOptionalFile(finalUrl, "/.well-known/security.txt", options.requestTimeoutMs),
    fetchOptionalFile(finalUrl, "/robots.txt", options.requestTimeoutMs),
    fetchOptionalFile(finalUrl, "/sitemap.xml", options.requestTimeoutMs),
  ]);
  const tlsInfo = finalUrl.startsWith("https://")
    ? await inspectTlsCertificate(new URL(finalUrl).hostname)
    : {
        supported: null,
        error: "TLS inspection not applicable because the final URL is not HTTPS.",
      };

  const findings = [
    ...analyzeTls(tlsInfo),
    ...analyzeRedirectPolicy(target, finalUrl, redirectInfo),
    ...headerAnalysis.findings,
    ...analyzeCookies(cookieInfo, finalUrl),
    ...crawl.findings,
    ...analyzeAuxiliaryFiles(auxiliaryFiles),
  ].sort((left, right) => severityWeight(right.severity) - severityWeight(left.severity));

  const summary = groupFindings(findings);
  const score = calculateRiskScore(findings);
  const risk = {
    score,
    band: scoreBand(score),
  };
  const coverage = {
    pages: crawl.pages,
    pagesCrawled: crawl.pages.length,
    maxPages: options.maxPages,
    crawlEnabled: options.includeSubpages,
  };
  const inventory = {
    totalForms: crawl.inventory.totalForms,
    totalPasswordForms: crawl.inventory.totalPasswordForms,
    externalScriptHosts: crawl.inventory.externalScriptHosts,
    loginPages: crawl.inventory.loginPages,
  };
  const report = buildNarrative({
    target,
    finalUrl,
    findings,
    summary,
    risk,
    coverage,
    inventory,
    options,
  });
  const scannedAt = new Date().toISOString();
  const markdown = buildMarkdownReport({
    target,
    finalUrl,
    scannedAt,
    findings,
    summary,
    risk,
    coverage,
    report,
    inventory,
    options,
  });

  return {
    product: "Sentinel Scan",
    version: "2.0.0",
    target,
    finalUrl,
    scannedAt,
    options,
    summary,
    risk,
    technologies: unique(crawl.technologies),
    transport: tlsInfo,
    redirectPolicy: redirectInfo,
    auxiliaryFiles,
    coverage,
    inventory,
    findings,
    report,
    markdown,
    scope: {
      mode: "passive-authorized-review",
      limitations: [
        "No active exploitation or credentialed testing is performed.",
        "Results are heuristic and should be validated manually before remediation or disclosure decisions.",
      ],
    },
  };
}
