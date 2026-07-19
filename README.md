# codebase-health-intelligence

[![npm version](https://img.shields.io/npm/v/codebase-health-intelligence?color=crimson)](https://www.npmjs.com/package/codebase-health-intelligence)
[![npm downloads](https://img.shields.io/npm/dw/codebase-health-intelligence)](https://www.npmjs.com/package/codebase-health-intelligence)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/ademyalcin27/codebase-health-intelligence/blob/main/LICENSE)
[![GitHub repo](https://img.shields.io/badge/GitHub-codebase--health--intelligence-181717?logo=github)](https://github.com/ademyalcin27/codebase-health-intelligence)

> **Your dependencies are silently breaking your codebase. This MCP server sees what `npm outdated` can't.**

`codebase-health-intelligence` is an [MCP](https://modelcontextprotocol.io) server that plugs directly into Claude (Desktop or Code) and gives you AI-ready, signal-driven dependency intelligence: risk scores, breaking change predictions, upgrade strategies, and maintenance signals — all grounded in real npm and GitHub data.

No hallucinations. No guesses. Every signal is fetched live.

---

## Why

| Without this | With this |
|---|---|
| `npm outdated` gives you a list | Risk scores show which ones actually matter |
| You guess what will break | Breaking change predictor tells you exactly |
| No safe upgrade order | Step-by-step plan with rollback commands |
| No context on why a package is risky | Signal-based explanations per package |

---

## Installation

### Global CLI

```bash
npm install -g codebase-health-intelligence
```

### npx (no install)

```bash
npx codebase-health-intelligence
```

---

## Wire into Claude

### Claude Code

```bash
claude mcp add codebase-health-intelligence \
  -e GITHUB_TOKEN=your_token \
  -- npx codebase-health-intelligence
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "codebase-health-intelligence": {
      "command": "npx",
      "args": ["codebase-health-intelligence"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_token"
      }
    }
  }
}
```

> **Tip:** Set `GITHUB_TOKEN` to avoid GitHub API rate limits (60 → 5,000 req/hr). [Create a token →](https://github.com/settings/tokens)

---

## Tools

Five MCP tools are exposed. Ask Claude to use any of them by name.

### `analyze_repo_health`

Full dependency analysis with a global health score (0–100), per-package risk breakdown, risk groups, and top critical issues.

```
Prompt: "Analyze the health of my dependencies in /path/to/project"
```

**Example output:**
```json
{
  "healthScore": 34,
  "healthLevel": "risky",
  "summary": "Several dependencies are showing maintenance or adoption problems.",
  "topIssues": [
    "3 critical risk packages detected",
    "47% of packages not published in over a year"
  ]
}
```

---

### `generate_upgrade_plan`

Step-by-step upgrade strategy ordered by safety — patch updates first, major bumps last — with rollback commands for every step.

```
Prompt: "Generate an upgrade plan for /path/to/project"
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

---

### `explain_dependency`

Signal-based explanation of why a package is risky or safe. Covers adoption, maintenance, and a concrete recommendation. Based entirely on live-fetched data.

```
Prompt: "Explain the risk of left-pad"
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

---

### `build_dependency_graph`

Enhanced dependency graph with blast radius scores, critical node detection, and circular dependency analysis.

```
Prompt: "Build the dependency graph for /path/to/project"
```

---

### `predict_breaking_changes`

Predicts which upgrades are likely to break your code, why, what areas are affected, and a confidence score.

```
Prompt: "What will break if I upgrade dependencies in /path/to/project?"
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
    "Type definitions may be incompatible with your current tsconfig"
  ],
  "reasoning": "This package jumped one major version. Major bumps almost always include breaking changes."
}
```

---

## Risk Scoring

Every package is scored 0–100 based on live signals:

| Signal | Penalty |
|---|---|
| Last publish > 365 days | +30 |
| Last publish > 1000 days | +50 |
| Weekly downloads < 1,000 | +15 |
| Weekly downloads < 100 | +30 |
| Last GitHub commit > 180 days | +20 |
| No repository / repo unavailable | +40 |
| Open issues > 200 | +10 |

| Score | Risk Level |
|---|---|
| 0–24 | `low` |
| 25–49 | `medium` |
| 50–74 | `high` |
| 75–100 | `critical` |

## Repository Health Score

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
  providers/                    # npm registry + GitHub API, caching & dedup
  core/
    analyzer.ts                 # reads package.json, fans out in batches of 10
    risk-score.ts               # additive penalty scoring
    graph-engine.ts             # blast radius, critical nodes, circular deps
    upgrade-planner.ts          # step-by-step upgrade strategy
    breaking-change-predictor.ts
  ai/
    explainer.ts                # rule-based signal explanation (no LLM required)
  scoring/
    system-health.ts            # repo-level health aggregation
  tools/                        # MCP tool wrappers
  server.ts                     # entry point — registers all tools
```

All npm and GitHub responses are cached in-memory for 10 minutes. Concurrent requests for the same package share a single in-flight fetch (request deduplication).

---

## Contributing

Issues and PRs welcome at [github.com/ademyalcin27/codebase-health-intelligence](https://github.com/ademyalcin27/codebase-health-intelligence).

## License

[MIT](./LICENSE) © Adem Yalçın

---

## One Piece

**Section Description:** The project aims to give developers a unique set of tools to combat the challenges in managing code dependencies, similar to how the legendary 'One Piece' treasure offers boundless prospects for those daring enough to seek it.

Much like the legendary treasure, which is sought after by pirates across the seas, this tool provides a treasure trove of information that is sought after by developers across the tech industry.**

It offers incredible insights and strategies analogous to how pirates strategize over territories.

It turns your codebase into an adventure full of discoveries just like the adventures faced by pirates in their journey for 'One Piece'.

Bold adventurers and developers would benefit greatly from the 'One Piece' section of this tool.

The treasure is not just gold and jewels but also wisdom and strategy, mirrored by the solutions offered by this tool for dependency management and enhancement.

Join the adventure!