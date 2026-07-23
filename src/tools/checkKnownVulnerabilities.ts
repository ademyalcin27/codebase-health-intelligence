
import { z } from 'zod';
import { promises as fs } from 'fs';
import path from 'path';

import { OsvVulnerability, queryBatch } from '../core/osv.js';

const checkKnownVulnerabilitiesInput = z.object({
  projectPath: z.string().default('.'),
});

async function getDependencies(
  projectPath: string
): Promise<Map<string, string>> {
  const packageJsonPath = path.join(projectPath, 'package.json');
  const packageLockJsonPath = path.join(projectPath, 'package-lock.json');

  const [packageJsonContent, packageLockJsonContent] = await Promise.all([
    fs.readFile(packageJsonPath, 'utf-8'),
    fs.readFile(packageLockJsonPath, 'utf-8'),
  ]);

  const packageJson = JSON.parse(packageJsonContent);
  const packageLockJson = JSON.parse(packageLockJsonContent);

  const dependencies = new Map<string, string>();

  const allDependencies = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {}),
  };

  for (const name of Object.keys(allDependencies)) {
    if (packageLockJson.packages?.[`node_modules/${name}`]) {
      dependencies.set(
        name,
        packageLockJson.packages[`node_modules/${name}`].version
      );
    }
  }

  return dependencies;
}

function groupVulnerabilitiesBySeverity(
  vulnerabilities: Map<string, OsvVulnerability[] | 'unknown'>
) {
  const grouped = {
    critical: new Map<string, OsvVulnerability[] | 'unknown'>(),
    high: new Map<string, OsvVulnerability[] | 'unknown'>(),
    medium: new Map<string, OsvVulnerability[] | 'unknown'>(),
    low: new Map<string, OsvVulnerability[] | 'unknown'>(),
    unknown: new Map<string, OsvVulnerability[] | 'unknown'>(),
  };

  for (const [pkg, vulns] of vulnerabilities.entries()) {
    if (vulns === 'unknown') {
      grouped.unknown.set(pkg, 'unknown');
      continue;
    }

    for (const vuln of vulns) {
      const severity =
        vuln.database_specific?.severity.toLowerCase() ?? 'unknown';

      switch (severity) {
        case 'critical':
          if (!grouped.critical.has(pkg)) grouped.critical.set(pkg, []);
          (grouped.critical.get(pkg) as OsvVulnerability[]).push(vuln);
          break;
        case 'high':
          if (!grouped.high.has(pkg)) grouped.high.set(pkg, []);
          (grouped.high.get(pkg) as OsvVulnerability[]).push(vuln);
          break;
        case 'medium':
          if (!grouped.medium.has(pkg)) grouped.medium.set(pkg, []);
          (grouped.medium.get(pkg) as OsvVulnerability[]).push(vuln);
          break;
        case 'low':
          if (!grouped.low.has(pkg)) grouped.low.set(pkg, []);
          (grouped.low.get(pkg) as OsvVulnerability[]).push(vuln);
          break;
        default:
          if (!grouped.unknown.has(pkg)) grouped.unknown.set(pkg, []);
          (grouped.unknown.get(pkg) as OsvVulnerability[]).push(vuln);
          break;
      }
    }
  }

  // Convert maps to objects for JSON output
  const result: Record<string, Record<string, OsvVulnerability[] | 'unknown'>> = {};
  for (const severity in grouped) {
    if (grouped[severity as keyof typeof grouped].size > 0) {
      result[severity] = Object.fromEntries(grouped[severity as keyof typeof grouped]);
    }
  }

  return result;
}

async function checkKnownVulnerabilities(
  input: z.infer<typeof checkKnownVulnerabilitiesInput>
) {
  const dependencies = await getDependencies(input.projectPath);
  const vulnerabilities = await queryBatch(dependencies);
  const groupedVulnerabilities =
    groupVulnerabilitiesBySeverity(vulnerabilities);

  return groupedVulnerabilities;
}

export const checkKnownVulnerabilitiesTool = {
  name: 'check_known_vulnerabilities',
  description: 'Checks for known vulnerabilities in project dependencies.',
  input: checkKnownVulnerabilitiesInput,
  run: checkKnownVulnerabilities,
};
