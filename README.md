# dependency-risk-mcp

> **Your dependencies are silently breaking your codebase.**

Most teams update packages reactively — after something breaks in production. `dependency-risk-mcp` is an AI Codebase Health & Upgrade Intelligence System that gives you the full picture before you ship: risk scores, breaking change predictions, upgrade strategies, and maintenance signals — all through the MCP protocol.

---

## Before vs After

| Before | After |
|---|---|
| `npm outdated` shows a list | Risk scores show which ones actually matter |
| You guess what's breaking | Breaking change predictor tells you exactly |
| No upgrade order | Step-by-step plan with rollback commands |
| No context on why | Signal-based explanations per package |

---

## Setup

```bash
npm install
npm run build
```

Set a GitHub token to avoid rate limits (5000 req/hr vs 60):

```bash
export GITHUB_TOKEN=ghp_your_token
```

Or add to `.env` (auto-loaded):
```
GITHUB_TOKEN=ghp_your_token
```

### Wire into Claude Code

```bash
claude mcp add dependency-risk-mcp \
  -e GITHUB_TOKEN=your_token \
  -- node /absolute/path/to/dist/server.js
```

### Wire into Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dependency-risk-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/dist/server.js"],
      "env": { "GITHUB_TOKEN": "your_token" }
    }
  }
}
```

---

## Tools

### `analyze_dependencies` (v1)
Fast dependency risk scan. Returns risk score + level per package, sorted by risk descending.

```json
{ "projectPath": "/path/to/project" }
```

### `get_package_risk` (v1)
Single package risk report.

```json
{ "packageName": "lodash" }
```

### `analyze_repo_health_v2` ⭐
Full analysis with global health score, risk groups, and top critical issues.

```json
{ "projectPath": "/path/to/project" }
```

**Example output:**
```json
{
  "healthScore": {
    "healthScore": 34,
    "healthLevel": "risky",
    "summary": "Several dependencies are showing maintenance or adoption problems.",
    "topIssues": [
      "3 critical risk packages detected",
      "47% of packages not published in over a year"
    ]
  }
}
```

### `generate_upgrade_plan` ⭐
Step-by-step upgrade strategy ordered by safety. Patch updates first, major bumps last.

```json
{ "projectPath": "/path/to/project" }
```

**Example step:**
```json
{
  "order": 1,
  "packageName": "zod",
  "action": "cautious-upgrade",
  "currentVersion": "^3.22.0",
  "targetVersion": "4.4.3",
  "upgradeCommand": "npm install zod@4.4.3",
  "rollbackCommand": "npm install zod@3.22.0",
  "warnings": ["Major version jump: 3.22.0 → 4.4.3"],
  "reasoning": "Major version upgrade. Breaking API changes likely. Test thoroughly."
}
```

### `explain_dependency`
Human-readable, signal-based explanation of a package's risk. No hallucinations — only real data.

```json
{ "packageName": "left-pad" }
```

**Example output:**
```json
{
  "verdict": "⚠️ left-pad has elevated risk",
  "signals": [
    { "label": "Last published", "value": "2958 days ago", "impact": "negative" },
    { "label": "Weekly downloads", "value": "1.3M/week", "impact": "positive" },
    { "label": "Last commit", "value": "2583 days ago", "impact": "negative" }
  ],
  "recommendation": "Review this dependency. Plan a replacement."
}
```

### `build_dependency_graph_v2`
Enhanced dependency graph with blast radius, critical node detection, and circular dependency analysis.

```json
{ "projectPath": "/path/to/project" }
```

### `predict_breaking_changes` ⭐
Predicts which upgrades are likely to break your code, why, and what areas are affected.

```json
{ "projectPath": "/path/to/project" }
```

**Example prediction:**
```json
{
  "packageName": "typescript",
  "impactSeverity": "breaking",
  "currentVersion": "5.8.3",
  "latestVersion": "6.0.3",
  "affectedAreas": ["Type System", "Compilation"],
  "likelyBreakingChanges": [
    "Major version bump: high probability of breaking API changes",
    "Type definitions may be incompatible with your TypeScript version"
  ],
  "reasoning": "This package jumped one major version. Major bumps almost always include breaking changes."
}
```

---

## Risk Scoring

| Signal | Penalty |
|---|---|
| Last publish > 365 days | +30 |
| Last publish > 1000 days | +50 |
| Weekly downloads < 1,000 | +15 |
| Weekly downloads < 100 | +30 |
| Last GitHub commit > 180 days | +20 |
| No repository / repo unavailable | +40 |
| Open issues > 200 | +10 |

| Score | Level |
|---|---|
| 0–24 | `low` |
| 25–49 | `medium` |
| 50–74 | `high` |
| 75–100 | `critical` |

## Repo Health Score

| Score | Level |
|---|---|
| 80–100 | `excellent` |
| 60–79 | `good` |
| 35–59 | `risky` |
| 0–34 | `critical` |

---

## Architecture

```
src/
  providers/         # npm registry + GitHub API with caching & dedup
  core/
    analyzer.ts      # reads package.json, fans out in batches of 10
    risk-score.ts    # additive penalty scoring function
    graph-engine.ts  # blast radius, critical nodes, circular deps
    upgrade-planner.ts          # step-by-step upgrade strategy
    breaking-change-predictor.ts # semver + heuristic impact analysis
  ai/
    explainer.ts     # rule-based signal explanation (no LLM required)
  scoring/
    system-health.ts # repo-level health aggregation
  tools/             # v1 + v2 MCP tool wrappers
  server.ts          # McpServer with all 7 registered tools
```

All npm and GitHub responses are cached in-memory for 10 minutes. Parallel API calls are deduplicated — concurrent requests for the same package share one in-flight fetch.
