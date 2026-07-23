
import { z } from 'zod';


const OSV_API_URL = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;

// Zod schemas for OSV API response
const OsvVulnerabilitySchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  affected: z.array(
    z.object({
      package: z.object({
        name: z.string(),
        ecosystem: z.string(),
      }),
      versions: z.array(z.string()),
      ranges: z
        .array(
          z.object({
            type: z.string(),
            repo: z.string().optional(),
            events: z.array(
              z.object({
                introduced: z.string().optional(),
                fixed: z.string().optional(),
              })
            ),
          })
        )
        .optional(),
    })
  ),
  references: z
    .array(
      z.object({
        type: z.string(),
        url: z.string(),
      })
    )
    .optional(),
  database_specific: z
    .object({
      severity: z.string().optional(),
    })
    .optional(),
  severities: z
    .array(
      z.object({
        type: z.string(),
        score: z.string(),
      })
    )
    .optional(),
});

const OsvBatchResponseSchema = z.object({
  results: z.array(z.object({ vulns: z.array(OsvVulnerabilitySchema).optional() })).optional(),
});

type OsvVulnerability = z.infer<typeof OsvVulnerabilitySchema>;

interface OsvBatchQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version: string;
}

const osvCache = new Map<string, OsvVulnerability[]>();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

async function queryOsvApi(queries: OsvBatchQuery[]): Promise<OsvVulnerability[][]> {
  const cacheKey = JSON.stringify(queries);
  if (osvCache.has(cacheKey)) {
    const cached = osvCache.get(cacheKey);
    if (cached) {
      return [cached];
    }
  }

  const results: OsvVulnerability[][] = [];
  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    try {
      const response = await fetch(`${OSV_API_URL}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: batch }),
      });

      if (!response.ok) {
        console.error(`OSV API request failed with status ${response.status}`);
        results.push(...Array(batch.length).fill([])); // Push empty arrays on failure
        continue;
      }

      const data = await response.json();
      const parsed = OsvBatchResponseSchema.safeParse(data);
      if (!parsed.success) {
        console.error('Failed to parse OSV response:', parsed.error);
        results.push(...Array(batch.length).fill([]));
        continue;
      }

      const batchResults = parsed.data.results?.map(r => r.vulns || []) || [];
      results.push(...batchResults);
    } catch (error) {
      console.error('Error querying OSV API:', error);
      results.push(...Array(batch.length).fill([]));
    }
  }

  if (results.length > 0) {
    osvCache.set(cacheKey, results.flat());
    setTimeout(() => osvCache.delete(cacheKey), CACHE_TTL);
  }

  return results;
}

export { queryOsvApi, OsvVulnerability, OsvBatchQuery };
