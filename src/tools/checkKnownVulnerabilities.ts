
import { z } from 'zod';
import { promises as fs } from 'fs';
import path from 'path';
import { OsvBatchQuery, OsvVulnerability, queryOsvApi } from '../core/osv.js';

const CheckKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string(),
});

type VulnerabilityInfo = {
  id: string;
  summary?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';
  affectedVersions: string[];
  fixedVersions?: string;
};

type VulnerabilityReport = {
  packageName: string;
  version: string;
  vulnerabilities: VulnerabilityInfo[];
};

async function checkKnownVulnerabilities(input: z.infer<typeof CheckKnownVulnerabilitiesSchema>) {
  const { projectPath } = input;
  const packageJsonPath = path.join(projectPath, 'package.json');
  const packageLockJsonPath = path.join(projectPath, 'package-lock.json');

  let dependencies: { [name: string]: string } = {};

  try {
    const packageJsonContents = await fs.readFile(packageJsonPath, 'utf-8');
    const packageJson = JSON.parse(packageJsonContents);
    dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

    if (await fs.stat(packageLockJsonPath).then(() => true).catch(() => false)) {
      const packageLockJsonContents = await fs.readFile(packageLockJsonPath, 'utf-8');
      const packageLockJson = JSON.parse(packageLockJsonContents);
      
      const lockfileDeps = Object.entries(packageLockJson.packages)
        .filter(([key, _]) => key !== '' && !key.startsWith('node_modules/'))
        .reduce((acc, [key, value]) => {
          const pkg = value as {version: string, dev?: boolean};
          // TODO: This is a simplistic way of getting the package name.
          // Consider using a more robust method.
          const name = key.split('node_modules/').pop() || key;
          acc[name] = pkg.version;
          return acc;
        }, {} as {[name: string]: string});
        
        dependencies = {...dependencies, ...lockfileDeps};
    }

  } catch (error) {
    console.error('Error reading package.json or package-lock.json:', error);
    return;
  }

  const queries: OsvBatchQuery[] = Object.entries(dependencies).map(([name, version]) => ({
    package: { name, ecosystem: 'npm' },
    version,
  }));

  const osvResults = await queryOsvApi(queries);

  const reports: VulnerabilityReport[] = [];
  for (let i = 0; i < queries.length; i++) {
    const query = queries[i];
    const result = osvResults[i];

    if (!result || result.length === 0) {
      continue;
    }

    const vulnerabilities: VulnerabilityInfo[] = result.map((vuln: OsvVulnerability) => {
      let severity: VulnerabilityInfo['severity'] = 'Unknown';
      let cvssScore: number | null = null;
      if (vuln.severities) {
        for (const s of vuln.severities) {
          if (s.type === 'CVSS_V3') {
            cvssScore = parseFloat(s.score);
            break;
          }
        }
      }

      if (cvssScore !== null) {
        if (cvssScore >= 9.0) severity = 'Critical';
        else if (cvssScore >= 7.0) severity = 'High';
        else if (cvssScore >= 4.0) severity = 'Medium';
        else if (cvssScore > 0) severity = 'Low';
      } else if(vuln.database_specific?.severity) {
        const dbSeverity = vuln.database_specific.severity.toUpperCase();
        if (dbSeverity === 'CRITICAL') severity = 'Critical';
        else if (dbSeverity === 'HIGH') severity = 'High';
        else if (dbSeverity === 'MODERATE') severity = 'Medium';
        else if (dbSeverity === 'LOW') severity = 'Low';
      }

      const affected = vuln.affected.find(a => a.package.name === query.package.name);

      const fixedEvent = affected?.ranges?.flatMap(r => r.events).find(e => e.fixed);

      return {
        id: vuln.id,
        summary: vuln.summary,
        severity,
        affectedVersions: affected?.versions || [],
        fixedVersions: fixedEvent?.fixed,
      };
    });

    reports.push({
      packageName: query.package.name,
      version: query.version,
      vulnerabilities,
    });
  }

  const reportsBySeverity: { [key in VulnerabilityInfo['severity']]?: { [pkg: string]: VulnerabilityInfo[] } } = {};

  for (const report of reports) {
    for (const vuln of report.vulnerabilities) {
      const { severity } = vuln;
      let severityGroup = reportsBySeverity[severity];
      if (!severityGroup) {
        severityGroup = {};
        reportsBySeverity[severity] = severityGroup;
      }
      
      const pkgId = `${report.packageName}@${report.version}`;
      let packageVulnerabilities = severityGroup[pkgId];
      if(!packageVulnerabilities){
        packageVulnerabilities = [];
        severityGroup[pkgId] = packageVulnerabilities;
      }
      packageVulnerabilities.push(vuln);
    }
  }

  const severities: VulnerabilityInfo['severity'][] = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
  let vulnerabilitiesFound = false;

  severities.forEach(severity => {
    const packages = reportsBySeverity[severity];
    if (packages && Object.keys(packages).length > 0) {
      vulnerabilitiesFound = true;
      console.log(`
--- ${severity.toUpperCase()} ---`);
      Object.entries(packages).forEach(([pkgId, vulns]) => {
        console.log(`
Package: ${pkgId}`);
        vulns.forEach(vuln => {
          console.log(`  Vulnerability ID: ${vuln.id}`);
          console.log(`  Summary: ${vuln.summary || 'Not available'}`);
          if (vuln.affectedVersions.length > 0) {
            console.log(`  Affected Versions: ${vuln.affectedVersions.join(', ')}`);
          }
          if (vuln.fixedVersions) {
            console.log(`  Fixed in: ${vuln.fixedVersions}`);
          }
        });
      });
    }
  });

  if (!vulnerabilitiesFound) {
    console.log('No known vulnerabilities found across all dependencies.');
  }
}

export { checkKnownVulnerabilities, CheckKnownVulnerabilitiesSchema };
