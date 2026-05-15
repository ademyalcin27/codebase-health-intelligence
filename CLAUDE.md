# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`dependency-risk-mcp` — an MCP server that analyzes npm dependencies and scores each one for supply-chain risk (0–100).

All source lives in `./`.

## Commands

```bash
cd ./
npm install          # install deps
npm run build        # tsc compile → dist/
npm run dev          # run via tsx (no compile needed)
npm start            # run compiled dist/server.js
npm run clean        # rm -rf dist
```

Optional env var — avoids GitHub API rate limits:

```bash
export GITHUB_TOKEN=ghp_...
```

## Architecture

```
src/
  types.ts                  # All shared interfaces (DependencyRisk, NpmMetadata, etc.)
  server.ts                 # MCP server entry: registers tools, routes CallToolRequest
  core/
    npm.ts                  # Fetches npm registry + weekly downloads; 10-min in-memory cache
    github.ts               # Fetches GitHub repo metadata; handles non-GitHub/missing repos
    risk-score.ts           # Pure scoring function — all penalty logic lives here
    analyzer.ts             # Orchestrates: reads package.json, fans out API calls in batches of 10, sorts results
  tools/
    analyzeDependencies.ts  # Thin wrapper + zod schema for analyze_dependencies tool
    getPackageRisk.ts       # Thin wrapper + zod schema for get_package_risk tool
```

**Data flow:** `server.ts` → `tools/*.ts` → `analyzer.ts` → parallel calls to `npm.ts` + `github.ts` → `risk-score.ts` → sorted `AnalysisResult`.

## Key design decisions

- **ESM throughout** (`"type": "module"` in package.json, `NodeNext` module resolution). All internal imports must use `.js` extensions.
- **Batched parallelism**: packages are analyzed in groups of 10 (`BATCH_SIZE` in `analyzer.ts`) to avoid hammering APIs.
- **Caching**: both `npm.ts` and `github.ts` maintain separate `Map` caches with a 10-minute TTL. Cache is process-scoped (lost on restart).
- **Scoring is purely additive** — penalties in `risk-score.ts` are summed and capped at 100. Add new signals there without touching other files.
- **Graceful degradation**: network errors in `analyzer.ts` catch per-package and assign score 50 / level "medium" rather than failing the whole analysis.
- **Server transport**: stdio only (`StdioServerTransport`). No HTTP.
