import { z } from 'zod';
import path from 'node:path';
import fs from 'node:fs/promises';
import { queryBatch, OsvQuery, OsvVulnerability } from '../core/osv.js';
import { validateProjectPath } from '../lib/validate-path.js';

const BATCH_SIZE = 100;

export const CheckKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().transform(validateProjectPath),
});

interface PackageInfo {
  name: string;
  version: string;
}

interface VulnerabilityResult {
  packageName: string;
  version: string;
  vulnerability: OsvVulnerability;
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

function getSeverity(vuln: OsvVulnerability): Severity {
    if (!vuln.severity) return 'UNKNOWN';

    // Find the highest severity score from CVSS v3.1
    let highestScore: number | null = null;
    for (const s of vuln.severity) {
        if (s.type === 'CVSS_V3') {
            const score = parseFloat(s.score);
            if (!isNaN(score) && (highestScore === null || score > highestScore)) {
                highestScore = score;
            }
        }
    }

    if (highestScore === null) return 'UNKNOWN';

    if (highestScore >= 9.0) return 'CRITICAL';
    if (highestScore >= 7.0) return 'HIGH';
    if (highestScore >= 4.0) return 'MEDIUM';
    if (highestScore >= 0.1) return 'LOW';
    return 'UNKNOWN';
}

async function getDependencies(projectPath: string): Promise<PackageInfo[]> {
  const packageJsonPath = path.join(projectPath, 'package.json');
  const packageLockJsonPath = path.join(projectPath, 'package-lock.json');

  try {
    const packageJsonContent = await fs.readFile(packageJsonPath, 'utf-8');
    const packageLockJsonContent = await fs.readFile(packageLockJsonPath, 'utf-8');
    const packageJson = JSON.parse(packageJsonContent);
    const packageLockJson = JSON.parse(packageLockJsonContent);

    const dependencies: PackageInfo[] = [];

    const directDependencies = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
    };

    for (const name in directDependencies) {
        if (packageLockJson.packages?.[`node_modules/${name}`]) {
            dependencies.push({
                name,
                version: packageLockJson.packages[`node_modules/${name}`].version,
            });
        }
    }

    return dependencies;
  } catch (error) {
    console.error('Error reading package.json or package-lock.json:', error);
    throw new Error('Could not read package files. Make sure projectPath is correct and files exist.');
  }
}


export async function checkKnownVulnerabilitiesTool(input: z.infer<typeof CheckKnownVulnerabilitiesSchema>): Promise<any> {
  const { projectPath } = input;
  const dependencies = await getDependencies(projectPath);

  if (dependencies.length === 0) {
    return { summary: 'No dependencies found.', results: {} };
  }

  const queries: OsvQuery[] = dependencies.map(dep => ({
    package: { name: dep.name, ecosystem: 'npm' },
    version: dep.version,
  }));

  const allVulnerabilities: VulnerabilityResult[] = [];

  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    const results = await queryBatch(batch);

    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      const dependency = dependencies[i + j];

      if (result === null) {
        // Error during fetch, mark as unknown
        // This could be represented in the output if desired
        continue;
      }

      for (const vuln of result) {
        allVulnerabilities.push({ 
          packageName: dependency.name, 
          version: dependency.version, 
          vulnerability: vuln 
        });
      }
    }
  }

  const groupedBySeverity = allVulnerabilities.reduce((acc, result) => {
      const severity = getSeverity(result.vulnerability);
      if (!acc[severity]) {
          acc[severity] = [];
      }

      const affectedVersion = result.vulnerability.affected.find(a => a.package.name === result.packageName);
      const fixedVersion = affectedVersion?.ranges?.find(r => r.type === 'SEMVER')?.events?.find(e => e.fixed)?.fixed;

      acc[severity].push({
          package: result.packageName,
          version: result.version,
          id: result.vulnerability.id,
          summary: result.vulnerability.summary,
          severity: getSeverity(result.vulnerability),
          affected_range: affectedVersion?.versions?.join(', ') || 'N/A',
          fixed_version: fixedVersion || 'N/A',
      });
      return acc;
  }, {} as Record<Severity, any[]>);

  return {
    summary: `Found ${allVulnerabilities.length} vulnerabilities across ${dependencies.length} dependencies.`,
    results: groupedBySeverity,
  };
}