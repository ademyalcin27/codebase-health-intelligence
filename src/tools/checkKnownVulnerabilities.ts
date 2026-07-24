
import { z } from "zod";
import { logger } from "../lib/logger.js";
import { readPackageJson } from "../core/analyzer.js";
import { queryOsv, type OsvVulnerability } from "../core/osv.js";
import { validateProjectPath } from "../lib/validate-path.js";

const BATCH_SIZE = 50;

export const CheckKnownVulnerabilitiesInput = z.object({
  projectPath: z.string().describe("The absolute path to the project directory containing a package.json."),
});

export type CheckKnownVulnerabilitiesInput = z.infer<typeof CheckKnownVulnerabilitiesInput>;

export interface Vulnerability {
  packageName: string;
  version: string;
  vulnerability: OsvVulnerability;
}

export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low" | "unknown";

export interface CheckKnownVulnerabilitiesOutput {
  vulnerabilities: Record<VulnerabilitySeverity, Vulnerability[]>;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
}

function getSeverity(vuln: OsvVulnerability): VulnerabilitySeverity {
  if (!vuln.severity || vuln.severity.length === 0) return "unknown";

  // Find the CVSS v3.1 score, otherwise take the first available one
  const cvssV3 = vuln.severity.find(s => s.type === 'CVSS_V3');
  const scoreStr = cvssV3 ? cvssV3.score : vuln.severity[0].score;
  const score = parseFloat(scoreStr);

  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";

  return "unknown";
}

export async function checkKnownVulnerabilities(
  input: CheckKnownVulnerabilitiesInput
): Promise<CheckKnownVulnerabilitiesOutput> {
  const { projectPath } = input;
  const validPath = await validateProjectPath(projectPath);

  logger.info("Checking for known vulnerabilities", { projectPath: validPath });

  const pkg = await readPackageJson(validPath);
  const dependencies = Object.entries(pkg.dependencies ?? {}).map(([name, version]) => ({ name, version }));

  const allVulnerabilities: Vulnerability[] = [];

  for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
    const batch = dependencies.slice(i, i + BATCH_SIZE);
    logger.debug("Querying OSV for batch", { batch: i / BATCH_SIZE + 1, size: batch.length });
    try {
      const results = await queryOsv(batch);
      for (const [packageName, vulns] of results.entries()) {
        if (vulns.length > 0) {
          const dep = dependencies.find(d => d.name === packageName)!;
          for (const v of vulns) {
            allVulnerabilities.push({ packageName, version: dep.version, vulnerability: v });
          }
        }
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn("Failed to query OSV for batch", { batch: i / BATCH_SIZE + 1, error: message });
      // Gracefully continue to the next batch
    }
  }

  const vulnerabilities: Record<VulnerabilitySeverity, Vulnerability[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    unknown: [],
  };

  for (const v of allVulnerabilities) {
    const severity = getSeverity(v.vulnerability);
    vulnerabilities[severity].push(v);
  }

  const summary = {
    total: allVulnerabilities.length,
    critical: vulnerabilities.critical.length,
    high: vulnerabilities.high.length,
    medium: vulnerabilities.medium.length,
    low: vulnerabilities.low.length,
    unknown: vulnerabilities.unknown.length,
  };

  logger.info("Vulnerability check complete", summary);

  return { vulnerabilities, summary };
}
