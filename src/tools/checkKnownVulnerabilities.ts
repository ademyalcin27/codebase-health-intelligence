
import { z } from 'zod';
import * as fs from 'fs/promises';
import * as path from 'path';
import { getVulnerabilitiesForPackages } from '../core/osv.js';
import { logger } from '../lib/logger.js';
import { Vulnerability } from '../types.js';

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().describe('The absolute path to the project to analyze.'),
});

type VulnerabilityBySeverity = {
  critical: Vulnerability[];
  high: Vulnerability[];
  medium: Vulnerability[];
  low: Vulnerability[];
  unknown: Vulnerability[];
};

export async function checkKnownVulnerabilities(
  input: z.infer<typeof checkKnownVulnerabilitiesSchema>
): Promise<VulnerabilityBySeverity> {
  const { projectPath } = input;

  const packageLockPath = path.join(projectPath, 'package-lock.json');

  const packages = new Map<string, string>();

  try {
    const packageLockContent = await fs.readFile(packageLockPath, 'utf-8');
    const packageLock = JSON.parse(packageLockContent);

    if (packageLock.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(packageLock.packages as Record<string, {version?: string}>)) {
        if (pkgPath === '' || !pkgInfo.version) {
          continue;
        }
        // pkgPath is like "node_modules/cowsay" or "node_modules/@types/node"
        const name = pkgPath.replace('node_modules/', '');
        packages.set(name, pkgInfo.version);
      }
    }
  } catch (error) {
    logger.error(`Could not read or parse package-lock.json at ${packageLockPath}`, { error: (error as Error).message });
    throw new Error('Failed to analyze project dependencies. Please ensure package-lock.json exists and is valid.');
  }

  if (packages.size === 0) {
    logger.info('No packages found in package-lock.json');
    return { critical: [], high: [], medium: [], low: [], unknown: [] };
  }
  
  const vulnerabilities = await getVulnerabilitiesForPackages(packages);
  
  const results: VulnerabilityBySeverity = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    unknown: [],
  };

  for (const [packageName, vulns] of vulnerabilities.entries()) {
    for (const vuln of vulns) {
      const severity = (vuln.severity || 'UNKNOWN').toLowerCase();
      switch (severity) {
        case 'critical':
          results.critical.push({ ...vuln, packageName });
          break;
        case 'high':
          results.high.push({ ...vuln, packageName });
          break;
        case 'medium':
          results.medium.push({ ...vuln, packageName });
          break;
        case 'low':
          results.low.push({ ...vuln, packageName });
          break;
        default:
          results.unknown.push({ ...vuln, packageName });
          break;
      }
    }
  }

  return results;
}
