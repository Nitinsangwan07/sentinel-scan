import { appConfig } from "../config/env.js";

function toSimpleExplanation(finding) {
  return {
    id: finding.id,
    title: finding.title,
    simpleExplanation: `${finding.title} points to a ${finding.category}-related control gap that should be manually validated.`,
    whyItMatters: finding.impact,
    suggestedFix: finding.remediation,
  };
}

export async function buildAiAssist(scan) {
  const topFindings = scan.findings.slice(0, 4).map(toSimpleExplanation);

  return {
    provider: appConfig.aiProvider,
    generatedAt: new Date().toISOString(),
    summary:
      scan.findings.length === 0
        ? "The passive review did not identify material issues, but authenticated and manual validation is still recommended."
        : `This scan found ${scan.summary.total} issue(s). Prioritize the high-confidence items first, then tighten transport, browser policy, and third-party trust boundaries.`,
    remediationPlan: scan.report.priorityActions.map((action) => action.action),
    findingExplanations: topFindings,
  };
}
