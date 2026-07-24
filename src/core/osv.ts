
import fetch from 'node-fetch';
import { z } from 'zod';
import { BoundedCache } from '../lib/bounded-cache.js';

// OSV API schema
const OsvQuery = z.object({
  commit: z.string().optional(),
  version: z.string().optional(),
  package: z.object({
    name: z.string(),
    ecosystem: z.string(),
  }),
});
export type OsvQuery = z.infer<typeof OsvQuery>;

const OsvVulnerability = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  modified: z.string(),
  published: z.string(),
  database_specific: z.any().optional(),
  references: z
    .array(
      z.object({
        type: z.string(),
        url: z.string(),
      })
    )
    .optional(),
  affected: z.array(
    z.object({
      package: z.object({
        name: z.string(),
        ecosystem: z.string(),
        purl: z.string().optional(),
      }),
      ranges: z
        .array(
          z.object({
            type: z.string(),
            repo: z.string().optional(),
            events: z.array(z.object({ introduced: z.string().optional(), fixed: z.string().optional() })),
          })
        )
        .optional(),
      versions: z.array(z.string()).optional(),
      database_specific: z.any().optional(),
    })
  ),
  severity: z
    .array(
      z.object({
        type: z.string(),
        score: z.string(),
      })
    )
    .optional(),
});
export type OsvVulnerability = z.infer<typeof OsvVulnerability>;

const OsvResponse = z.object({
  vulns: z.array(OsvVulnerability),
});

const BatchedOsvResponse = z.object({
  results: z.array(OsvResponse),
});

// In-memory cache for OSV responses
const cache = new BoundedCache<OsvVulnerability[]>(1000, 10 * 60 * 1000); // 1000 items, 10 min TTL

const OSV_API_URL = 'https://api.osv.dev/v1/querybatch';

export async function queryBatch(queries: OsvQuery[]): Promise<(OsvVulnerability[] | null)[]> {
  const results: (OsvVulnerability[] | null)[] = [];
  const uncachedQueries: OsvQuery[] = [];
  const queryIndexMap: number[] = []; // maps uncached queries back to their original indices

  // Check cache first
  for (let i = 0; i < queries.length; i++) {
    const query = queries[i];
    const key = `${query.package.name}@${query.version}`;
    const cached = cache.get(key);
    if (cached) {
      results[i] = cached;
    } else {
      uncachedQueries.push(query);
      queryIndexMap.push(i);
      results[i] = null; // Placeholder
    }
  }

  if (uncachedQueries.length === 0) {
    return results;
  }

  try {
    const res = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries: uncachedQueries }),
    });

    if (!res.ok) {
      console.error(`OSV API request failed with status ${res.status}`);
      // Return null for all uncached queries as we can't fetch them
      for (const originalIndex of queryIndexMap) {
        results[originalIndex] = null;
      }
      return results;
    }

    const rawResponse = await res.json();
    const parsedResponse = BatchedOsvResponse.safeParse(rawResponse);

    if (!parsedResponse.success) {
      console.error('Failed to parse OSV response:', parsedResponse.error);
      for (const originalIndex of queryIndexMap) {
        results[originalIndex] = null;
      }
      return results;
    }

    // Process and cache new results
    for (let i = 0; i < parsedResponse.data.results.length; i++) {
      const originalIndex = queryIndexMap[i];
      const query = uncachedQueries[i];
      const key = `${query.package.name}@${query.version}`;
      const vulns = parsedResponse.data.results[i].vulns;

      results[originalIndex] = vulns;
      cache.set(key, vulns);
    }
    return results;
  } catch (error) {
    console.error('Network error during OSV API call:', error);
    for (const originalIndex of queryIndexMap) {
      results[originalIndex] = null; // Mark as unknown on network error
    }
    return results;
  }
}
