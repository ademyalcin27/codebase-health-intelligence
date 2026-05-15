import type { GitHubMetadata } from "../types.js";
import { fetchWithRetry } from "../lib/fetch-with-retry.js";
import { BoundedCache } from "../lib/bounded-cache.js";
import { logger } from "../lib/logger.js";

const cache = new BoundedCache<GitHubMetadata>(500, 10 * 60 * 1000);
const inflight = new Map<string, Promise<GitHubMetadata>>();

function daysSince(dateStr: string): number {
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86_400_000);
}

function parseGitHubOwnerRepo(repoUrl: string): { owner: string; repo: string } | null {
  try {
    const url = new URL(repoUrl);
    if (!url.hostname.includes("github.com")) return null;
    const parts = url.pathname.replace(/^\//, "").replace(/\.git$/, "").split("/");
    if (parts.length < 2 || !parts[0] || !parts[1]) return null;
    return { owner: parts[0], repo: parts[1] };
  } catch {
    return null;
  }
}

const notAvailable = (owner: string | null = null, repo: string | null = null): GitHubMetadata => ({
  owner, repo, openIssues: null, lastPushedAt: null, daysSinceLastCommit: null, available: false,
});

async function _fetch(repositoryUrl: string): Promise<GitHubMetadata> {
  const parsed = parseGitHubOwnerRepo(repositoryUrl);
  if (!parsed) return notAvailable();

  const { owner, repo } = parsed;
  const cacheKey = `${owner}/${repo}`;

  const cached = cache.get(cacheKey);
  if (cached) return cached;

  logger.debug("Fetching GitHub metadata", { owner, repo });

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "codebase-health-intelligence/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  let response;
  try {
    response = await fetchWithRetry(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  } catch (err) {
    logger.warn("GitHub fetch failed", { owner, repo, error: String(err) });
    return notAvailable(owner, repo);
  }

  if (response.status === 404) {
    logger.debug("GitHub repo not found", { owner, repo });
    const result = notAvailable(owner, repo);
    cache.set(cacheKey, result);
    return result;
  }

  if (!response.ok) {
    logger.warn("GitHub API returned non-OK status", { owner, repo, status: response.status });
    return notAvailable(owner, repo);
  }

  const data = (await response.json()) as { open_issues_count?: number; pushed_at?: string };
  const lastPushedAt = data.pushed_at ?? null;
  const result: GitHubMetadata = {
    owner, repo,
    openIssues: data.open_issues_count ?? null,
    lastPushedAt,
    daysSinceLastCommit: lastPushedAt ? daysSince(lastPushedAt) : null,
    available: true,
  };

  cache.set(cacheKey, result);
  return result;
}

export async function fetchGitHubMetadata(repositoryUrl: string | null): Promise<GitHubMetadata> {
  if (!repositoryUrl) return notAvailable();
  const existing = inflight.get(repositoryUrl);
  if (existing) return existing;
  const promise = _fetch(repositoryUrl).finally(() => inflight.delete(repositoryUrl));
  inflight.set(repositoryUrl, promise);
  return promise;
}
