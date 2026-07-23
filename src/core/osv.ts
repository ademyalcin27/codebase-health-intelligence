import fs from 'fs/promises';
import path from 'path';
import { BoundedCache } from '../lib/bounded-cache.js';
import { fetchWithRetry } from '../lib/fetch-with-retry.js';

const OSV_API_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000;

interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  aliases: string[];
  modified: string;
  published: string;
  database_specific: any;
  references: { type: string; url: string }[];
  affected: {
    package: { ecosystem: string; name: string; purl: string };
    ranges: { type: string; repo: string; events: any[] }[];
    versions: string[];
    database_specific: any;
    ecosystem_specific: any;
  }[];
  severity: {
    type: string;
    score: string;
  }[];
  schema_version: string;
}

interface Vulnerability {
  id: string;
  summary: string;
  severity: string;
  affectedVersions: string[];
  fixedVersion: string | null;
}

export interface GroupedVulnerabilities {
  critical: Vulnerability[];
  high: Vulnerability[];
  medium: Vulnerability[];
  low: Vulnerability[];
  unknown: Vulnerability[];
}

const cache = new BoundedCache<GroupedVulnerabilities>(100, 10 * 60 * 1000);

async function getDependencies(projectPath: string) {
  const packageJsonPath = path.join(projectPath, 'package.json');
  const packageLockJsonPath = path.join(projectPath, 'package-lock.json');

  const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf-8'));

  const dependencies: { [name: string]: string } = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  let allDependencies: { name: string; version: string }[] = [];

  try {
    const packageLockJson = JSON.parse(await fs.readFile(packageLockJsonPath, 'utf-8'));
    allDependencies = Object.entries(packageLockJson.packages)
      .filter(([key]) => key.startsWith('node_modules/'))
      .map(([key, value]: [string, any]) => ({
        name: key.replace(/^node_modules\//, ''),
        version: value.version,
      }));
  } catch (error) {
    // Fallback to package.json if package-lock.json is not available
    allDependencies = Object.entries(dependencies).map(([name, version]) => ({ name, version }));
  }

  return allDependencies.map(dep => ({
    ecosystem: 'npm',
    name: dep.name,
    version: dep.version,
  }));
}

function groupVulnerabilities(
  vulnerabilities: OsvVulnerability[],
): GroupedVulnerabilities {
  const grouped: GroupedVulnerabilities = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    unknown: [],
  };

  for (const vuln of vulnerabilities) {
    const severity = (vuln.severity?.[0]?.score ?? 'unknown').toLowerCase();
    const fixedVersion = vuln.affected[0]?.database_specific?.fixed_version ?? null;

    const vulnerability: Vulnerability = {
      id: vuln.id,
      summary: vuln.summary,
      severity,
      affectedVersions: vuln.affected.flatMap(a => a.versions),
      fixedVersion,
    };

    if (severity.startsWith('cvss_v3')) {
      const score = parseFloat(severity.split(':')[1]);
      if (score >= 9.0) grouped.critical.push(vulnerability);
      else if (score >= 7.0) grouped.high.push(vulnerability);
      else if (score >= 4.0) grouped.medium.push(vulnerability);
      else grouped.low.push(vulnerability);
    } else {
      grouped.unknown.push(vulnerability);
    }
  }

  return grouped;
}

export async function getVulnerabilities(
  projectPath: string,
): Promise<GroupedVulnerabilities> {
  const cached = cache.get(projectPath);
  if (cached) {
    return cached;
  }

  const dependencies = await getDependencies(projectPath);
  const queries = dependencies.map(dep => ({ package: { name: dep.name, ecosystem: dep.ecosystem }, version: dep.version }));

  const allVulnerabilities: OsvVulnerability[] = [];

  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    try {
      const response = await fetchWithRetry(OSV_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: batch }),
      });

      if (response.ok) {
        const result = await response.json() as { results: { vulns: OsvVulnerability[] }[] };
        for(const res of result.results){
          if(res.vulns){
            allVulnerabilities.push(...res.vulns);
          }
        }
      }
    } catch (error) {
      console.error('Error fetching vulnerabilities from OSV.dev', error);
    }
  }

  const grouped = groupVulnerabilities(allVulnerabilities);
  cache.set(projectPath, grouped);
  return grouped;
}
