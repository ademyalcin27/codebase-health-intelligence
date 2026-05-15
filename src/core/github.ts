import fetch from "node-fetch";
import type { GitHubMetadata } from "../types.js";

// In-memory cache: "owner/repo" → { data, fetchedAt }
const cache = new Map<string, { data: GitHubMetadata; fetchedAt: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000;

function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime();
  return Math.floor((Date.now() - then) / (1000 * 60 * 60 * 24));
}

function parseGitHubOwnerRepo(repoUrl: string): { owner: string; repo: string } | null {
  try {
    const url = new URL(repoUrl);
    if (!url.hostname.includes("github.com")) return null;
    const parts = url.pathname.replace(/^\//, "").replace(/\.git$/, "").split("/");
    if (parts.length < 2) return null;
    return { owner: parts[0], repo: parts[1] };
  } catch {
    return null;
  }
}

const notAvailable = (owner: string | null = null, repo: string | null = null): GitHubMetadata => ({
  owner,
  repo,
  openIssues: null,
  lastPushedAt: null,
  daysSinceLastCommit: null,
  available: false,
});

export async function fetchGitHubMetadata(repositoryUrl: string | null): Promise<GitHubMetadata> {
  if (!repositoryUrl) return notAvailable();

  const parsed = parseGitHubOwnerRepo(repositoryUrl);
  if (!parsed) return notAvailable();

  const { owner, repo } = parsed;
  const cacheKey = `${owner}/${repo}`;

  const cached = cache.get(cacheKey);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "dependency-risk-mcp/1.0",
  };

  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  let response;
  try {
    response = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  } catch {
    return notAvailable(owner, repo);
  }

  if (!response.ok) {
    return notAvailable(owner, repo);
  }

  const data = (await response.json()) as {
    open_issues_count?: number;
    pushed_at?: string;
  };

  const lastPushedAt = data.pushed_at ?? null;
  const result: GitHubMetadata = {
    owner,
    repo,
    openIssues: data.open_issues_count ?? null,
    lastPushedAt,
    daysSinceLastCommit: lastPushedAt ? daysSince(lastPushedAt) : null,
    available: true,
  };

  cache.set(cacheKey, { data: result, fetchedAt: Date.now() });
  return result;
}
