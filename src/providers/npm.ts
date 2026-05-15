import type { NpmMetadata } from "../types.js";
import { fetchWithRetry } from "../lib/fetch-with-retry.js";
import { BoundedCache } from "../lib/bounded-cache.js";
import { logger } from "../lib/logger.js";

const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

const cache = new BoundedCache<NpmMetadata>(500, 10 * 60 * 1000);
const inflight = new Map<string, Promise<NpmMetadata>>();

function daysSince(dateStr: string): number {
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86_400_000);
}

function extractRepoUrl(repository: unknown): string | null {
  if (!repository) return null;
  if (typeof repository === "string") {
    return repository.startsWith("http") ? repository : `https://github.com/${repository}`;
  }
  if (typeof repository === "object" && repository !== null && "url" in repository) {
    return (repository as { url: string }).url
      .replace(/^git\+/, "")
      .replace(/^git:\/\//, "https://")
      .replace(/\.git$/, "");
  }
  return null;
}

async function _fetch(packageName: string): Promise<NpmMetadata> {
  const cached = cache.get(packageName);
  if (cached) return cached;

  logger.debug("Fetching npm metadata", { package: packageName });

  const [registryRes, downloadsRes] = await Promise.allSettled([
    fetchWithRetry(`${NPM_REGISTRY}/${encodeURIComponent(packageName)}`),
    fetchWithRetry(`${NPM_DOWNLOADS_API}/${encodeURIComponent(packageName)}`),
  ]);

  if (registryRes.status === "rejected") {
    throw new Error(`npm registry unreachable for "${packageName}": ${String(registryRes.reason)}`);
  }
  if (!registryRes.value.ok) {
    throw new Error(`npm registry returned ${registryRes.value.status} for "${packageName}"`);
  }

  const registryData = (await registryRes.value.json()) as Record<string, unknown>;
  const distTags = registryData["dist-tags"] as Record<string, string> | undefined;
  const latestVersion = distTags?.latest ?? "unknown";
  const times = registryData["time"] as Record<string, string> | undefined;
  const publishedAt = times?.[latestVersion] ?? null;
  const daysSincePublish = publishedAt ? daysSince(publishedAt) : null;
  const latestMeta = (
    (registryData["versions"] as Record<string, unknown> | undefined)?.[latestVersion] ?? {}
  ) as Record<string, unknown>;
  const repositoryUrl = extractRepoUrl(latestMeta["repository"]);

  let weeklyDownloads: number | null = null;
  if (downloadsRes.status === "fulfilled" && downloadsRes.value.ok) {
    const dlData = (await downloadsRes.value.json()) as { downloads?: number };
    weeklyDownloads = dlData.downloads ?? null;
  } else {
    logger.debug("Downloads data unavailable", { package: packageName });
  }

  const data: NpmMetadata = { latestVersion, publishedAt, daysSincePublish, weeklyDownloads, repositoryUrl };
  cache.set(packageName, data);
  return data;
}

export async function fetchNpmMetadata(packageName: string): Promise<NpmMetadata> {
  const existing = inflight.get(packageName);
  if (existing) return existing;
  const promise = _fetch(packageName).finally(() => inflight.delete(packageName));
  inflight.set(packageName, promise);
  return promise;
}
