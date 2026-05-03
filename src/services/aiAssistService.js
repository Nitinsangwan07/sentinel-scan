import { appConfig } from "../config/env.js";

function toSimpleExplanation(finding) {
  return {
    id: finding.id,
    title: finding.title,
    simpleExplanation: `${finding.title} means the site may be missing a defensive safeguard that reduces exposure to ${finding.category}-related risk.`,
    whyItMatters: finding.impact,
    suggestedFix: finding.remediation,
  };
}

export async function buildAiAssist(scan) {
  const topFindings = scan.findings.slice(0, 5).map(toSimpleExplanation);

  return {
    provider: appConfig.aiProvider,
    generatedAt: new Date().toISOString(),
    summary:
      scan.findings.length === 0
        ? "The passive review did not identify material issues, but authenticated and manual validation is still recommended."
        : `This scan found ${scan.summary.total} issue(s). The most important work is to address the highest-severity findings first, then tighten browser-facing controls and third-party dependencies.`,
    remediationPlan: scan.report.priorityActions.map((action) => action.action),
    findingExplanations: topFindings,
  };
}
