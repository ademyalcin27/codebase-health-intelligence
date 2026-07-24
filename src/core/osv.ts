import { BoundedCache } from '../lib/bounded-cache.js';
import { fetchWithRetry } from '../lib/fetch-with-retry.js';
import { logger } from '../lib/logger.js';

const OSV_API_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 100;

interface OsvQuery {
  package: {
    name: string;
    ecosystem: 'npm';
  };
  version: string;
}

interface OsvResponse {
  vulns: {
    id: string;
    severity: {
      type: string;
      score: string;
    }[];
    affected: {
      ranges: {
        type: string;
        events: {
          introduced?: string;
          fixed?: string;
        }[];
      }[];
    }[];
  }[];
}

const cache = new BoundedCache<OsvResponse>(1000, 10 * 60 * 1000);

export async function queryOsv(
  packages: { name: string; version: string }[]
): Promise<Map<string, OsvResponse | null>> {
  const results = new Map<string, OsvResponse | null>();
  const queries: OsvQuery[] = [];

  for (const pkg of packages) {
    const cacheKey = `${pkg.name}@${pkg.version}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      results.set(cacheKey, cached);
    } else {
      queries.push({
        package: { name: pkg.name, ecosystem: 'npm' },
        version: pkg.version,
      });
    }
  }

  if (queries.length === 0) {
    return results;
  }

  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    try {
      const res = await fetchWithRetry(OSV_API_URL, {
        method: 'POST',
        body: JSON.stringify({ queries: batch }),
      });

      if (!res.ok) {
        logger.error(`OSV API request failed with status ${res.status}`);
        for (const query of batch) {
          results.set(`${query.package.name}@${query.version}`, null);
        }
        continue;
      }

      const data = (await res.json()) as { results: OsvResponse[] };
      for (let j = 0; j < batch.length; j++) {
        const query = batch[j];
        const result = data.results[j];
        const cacheKey = `${query.package.name}@${query.version}`;
        cache.set(cacheKey, result);
        results.set(cacheKey, result);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error querying OSV API', { error: message });
      for (const query of batch) {
        results.set(`${query.package.name}@${query.version}`, null);
      }
    }
  }

  return results;
}
