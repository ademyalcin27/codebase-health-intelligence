
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

  const groupedBySeverity = {
    Critical: [] as VulnerabilityReport[],
    High: [] as VulnerabilityReport[],
    Medium: [] as VulnerabilityReport[],
    Low: [] as VulnerabilityReport[],
    Unknown: [] as VulnerabilityReport[],
  };
  
  for(const report of reports){
      for(const vuln of report.vulnerabilities){
          const severityGroup = groupedBySeverity[vuln.severity];
          if(severityGroup){
              const existingReport = severityGroup.find(r => r.packageName === report.packageName && r.version === report.version);
              if(existingReport){
                existingReport.vulnerabilities.push(vuln);
              } else {
                severityGroup.push({
                    packageName: report.packageName,
                    version: report.version,
                    vulnerabilities: [vuln]
                });
              }
          }
      }
  }


  for (const [severity, reports] of Object.entries(groupedBySeverity)) {
    if (reports.length > 0) {
      console.log(`--- ${severity} ---`);
      for (const report of reports) {
        console.log(`Package: ${report.packageName}@${report.version}`);
        for (const vuln of report.vulnerabilities) {
          console.log(`  ID: ${vuln.id}`);
          if (vuln.summary) console.log(`  Summary: ${vuln.summary}`);
          if (vuln.fixedVersions) console.log(`  Fixed in: ${vuln.fixedVersions}`);
        }
      }
    }
  }
}

export { checkKnownVulnerabilities, CheckKnownVulnerabilitiesSchema };
