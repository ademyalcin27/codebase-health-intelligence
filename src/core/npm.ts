import fetch from "node-fetch";
import type { NpmMetadata } from "../types.js";

const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

// In-memory cache: packageName → { data, fetchedAt }
const cache = new Map<string, { data: NpmMetadata; fetchedAt: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime();
  const now = Date.now();
  return Math.floor((now - then) / (1000 * 60 * 60 * 24));
}

function extractRepoUrl(repository: unknown): string | null {
  if (!repository) return null;

  if (typeof repository === "string") {
    return repository.startsWith("http") ? repository : `https://github.com/${repository}`;
  }

  if (typeof repository === "object" && repository !== null && "url" in repository) {
    const url = (repository as { url: string }).url;
    return url
      .replace(/^git\+/, "")
      .replace(/^git:\/\//, "https://")
      .replace(/\.git$/, "");
  }

  return null;
}

export async function fetchNpmMetadata(packageName: string): Promise<NpmMetadata> {
  const cached = cache.get(packageName);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  const [registryRes, downloadsRes] = await Promise.allSettled([
    fetch(`${NPM_REGISTRY}/${encodeURIComponent(packageName)}`),
    fetch(`${NPM_DOWNLOADS_API}/${encodeURIComponent(packageName)}`),
  ]);

  if (registryRes.status === "rejected" || !registryRes.value.ok) {
    throw new Error(`Failed to fetch npm metadata for "${packageName}"`);
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
  }

  const data: NpmMetadata = {
    latestVersion,
    publishedAt,
    daysSincePublish,
    weeklyDownloads,
    repositoryUrl,
  };

  cache.set(packageName, { data, fetchedAt: Date.now() });
  return data;
}
