import { z } from 'zod';
import { promises as fs } from 'fs';
import path from 'path';
import { queryOsv } from '../core/osv.js';
import { validateProjectPath } from '../lib/validate-path.js';

export const checkKnownVulnerabilitiesRequest = z.object({
  projectPath: z.string(),
});

export type CheckKnownVulnerabilitiesRequest = z.infer<
  typeof checkKnownVulnerabilitiesRequest
>;

export const checkKnownVulnerabilities = async (
  req: CheckKnownVulnerabilitiesRequest
) => {
  const { projectPath } = req;
  await validateProjectPath(projectPath);

  const packageJsonPath = path.join(projectPath, 'package.json');
  const packageLockJsonPath = path.join(projectPath, 'package-lock.json');

  const [packageJsonContent, packageLockJsonContent] = await Promise.all([
    fs.readFile(packageJsonPath, 'utf-8'),
    fs.readFile(packageLockJsonPath, 'utf-8'),
  ]);

  const packageJson = JSON.parse(packageJsonContent);
  const packageLockJson = JSON.parse(packageLockJsonContent);

  const packages = Object.entries(packageLockJson.packages)
    .filter(([key]) => key.startsWith('node_modules/'))
    .map(([key, value]) => ({
      name: (value as any).name ?? key.substring(key.lastIndexOf('/') + 1),
      version: (value as any).version,
    }));

  const osvResults = await queryOsv(packages);

  const vulnerabilities = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    unknown: [],
  };

  for (const [key, result] of osvResults.entries()) {
    if (result === null) {
      (vulnerabilities.unknown as any[]).push({ package: key });
      continue;
    }

    if (result.vulns) {
      for (const vuln of result.vulns) {
        const severity = vuln.severity?.[0]?.score.toLowerCase() ?? 'unknown';
        const fixedVersion = vuln.affected?.[0]?.ranges?.[0]?.events?.[1]?.fixed;

        const report = {
          package: key,
          id: vuln.id,
          severity,
          fixedVersion,
        };

        if (severity in vulnerabilities) {
          (vulnerabilities[severity as keyof typeof vulnerabilities] as any[]).push(
            report
          );
        } else {
          (vulnerabilities.unknown as any[]).push(report);
        }
      }
    }
  }

  return vulnerabilities;
};
