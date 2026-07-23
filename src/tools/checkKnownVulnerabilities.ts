// src/tools/checkKnownVulnerabilities.ts
import { z } from 'zod';
import { promises as fs } from 'fs';
import path from 'path';
import { getVulnerabilitiesForPackages, Vulnerability } from '../core/osv.js';
import { logger } from '../lib/logger.js';
import { validateProjectPath } from '../lib/validate-path.js';

const CheckKnownVulnerabilitiesInputSchema = z.object({
  projectPath: z.string().min(1, 'Project path is required.'),
});

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

interface GroupedVulnerabilities {
  critical: Vulnerability[];
  high: Vulnerability[];
  medium: Vulnerability[];
  low: Vulnerability[];
  unknown: Vulnerability[];
}

function getSeverity(vuln: Vulnerability): Severity {
    if (!vuln.severity) return 'UNKNOWN';
    const cvssV3 = vuln.severity.find(s => s.type === 'CVSS_V3');
    if (cvssV3) {
        const score = parseFloat(cvssV3.score);
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        if (score > 0) return 'LOW';
    }
    return 'UNKNOWN';
}

async function checkKnownVulnerabilities(input: z.infer<typeof CheckKnownVulnerabilitiesInputSchema>): Promise<GroupedVulnerabilities> {
  const { projectPath } = input;
  await validateProjectPath(projectPath);

  const packageJsonPath = path.join(projectPath, 'package.json');
  let packageJson;
  try {
    const data = await fs.readFile(packageJsonPath, 'utf8');
    packageJson = JSON.parse(data);
  } catch (error) {
    logger.error(`Failed to read or parse package.json at ${packageJsonPath}`, { error });
    throw new Error(`Could not find or parse package.json at specified project path.`);
  }

  const dependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  const packages = Object.entries(dependencies).map(([name, version]) => ({
    name,
    version: version as string,
  }));

  const vulnerabilities = await getVulnerabilitiesForPackages(packages);

  const groupedVulnerabilities: GroupedVulnerabilities = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    unknown: [],
  };

  for (const vuln of vulnerabilities) {
    const severity = getSeverity(vuln);
    switch (severity) {
        case 'CRITICAL':
            groupedVulnerabilities.critical.push(vuln);
            break;
        case 'HIGH':
            groupedVulnerabilities.high.push(vuln);
            break;
        case 'MEDIUM':
            groupedVulnerabilities.medium.push(vuln);
            break;
        case 'LOW':
            groupedVulnerabilities.low.push(vuln);
            break;
        default:
            groupedVulnerabilities.unknown.push(vuln);
            break;
    }
  }

  return groupedVulnerabilities;
}

export const checkKnownVulnerabilitiesTool = {
  name: 'check_known_vulnerabilities',
  description: 'Scans project dependencies for known vulnerabilities using OSV.dev.',
  inputSchema: CheckKnownVulnerabilitiesInputSchema,
  execute: checkKnownVulnerabilities,
};
