import { z } from "zod";
import { Vulnerability } from "../types.js";

const OSV_API_URL = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE = 100;

const osvApiResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(
        z.object({
          id: z.string(),
          summary: z.string(),
          details: z.string(),
          aliases: z.array(z.string()),
          modified: z.string(),
          published: z.string(),
          database_specific: z.object({
            severity: z.string(),
          }),
        })
      ),
    })
  ),
});

const cache = new Map<string, { timestamp: number; data: any }>();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

async function queryOsv(
  packages: { name: string; version: string }[]
): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const queries = batch.map((p) => ({
      package: {
        name: p.name,
        ecosystem: "npm",
      },
      version: p.version,
    }));

    const cacheKey = JSON.stringify(queries);
    const cached = cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      vulnerabilities.push(...cached.data);
      continue;
    }

    try {
      const response = await fetch(OSV_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
      });

      if (!response.ok) {
        console.error(`OSV API request failed with status: ${response.status}`);
        batch.forEach((p) =>
          vulnerabilities.push({
            packageName: p.name,
            version: p.version,
            severity: "unknown",
            summary: "Failed to fetch vulnerability data",
            details: `OSV API request failed with status: ${response.status}`,
            affected: [],
            references: [],
          })
        );
        continue;
      }

      const data = await response.json();
      const parsedData = osvApiResponseSchema.parse(data);

      const batchVulnerabilities: Vulnerability[] = [];
      parsedData.results.forEach((result, index) => {
        const pkg = batch[index];
        if (result.vulns && result.vulns.length > 0) {
          result.vulns.forEach((vuln) => {
            batchVulnerabilities.push({
              packageName: pkg.name,
              version: pkg.version,
              severity: vuln.database_specific.severity.toLowerCase(),
              summary: vuln.summary,
              details: vuln.details,
              id: vuln.id,
              affected: [],
              references: [],
            });
          });
        }
      });
      cache.set(cacheKey, {
        timestamp: Date.now(),
        data: batchVulnerabilities,
      });
      vulnerabilities.push(...batchVulnerabilities);
    } catch (error) {
      console.error("Error querying OSV API:", error);
      batch.forEach((p) =>
        vulnerabilities.push({
          packageName: p.name,
          version: p.version,
          severity: "unknown",
          summary: "Failed to fetch vulnerability data",
          details: error instanceof Error ? error.message : String(error),
          affected: [],
          references: [],
        })
      );
    }
  }
  return vulnerabilities;
}

export { queryOsv };
