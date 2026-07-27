// ─── Base Types ───────────────────────────────────────────────────────────────

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type HealthLevel = "excellent" | "good" | "risky" | "critical";
export type ImpactSeverity = "none" | "low" | "medium" | "high" | "breaking";

// ─── Provider Data ────────────────────────────────────────────────────────────

export interface NpmMetadata {
  latestVersion: string;
  publishedAt: string | null;
  daysSincePublish: number | null;
  weeklyDownloads: number | null;
  repositoryUrl: string | null;
}

export interface GitHubMetadata {
  owner: string | null;
  repo: string | null;
  openIssues: number | null;
  lastPushedAt: string | null;
  daysSinceLastCommit: number | null;
  available: boolean;
}

// ─── Risk Scoring ─────────────────────────────────────────────────────────────

export interface ScoreBreakdown {
  stalePublish: number;
  lowDownloads: number;
  staleCommit: number;
  missingRepo: number;
  highIssues: number;
  total: number;
}

export interface DependencyRisk {
  name: string;
  version: string;
  riskScore: number;
  riskLevel: RiskLevel;
  npm: NpmMetadata;
  github: GitHubMetadata;
  scoreBreakdown: ScoreBreakdown;
}

// ─── Graph ────────────────────────────────────────────────────────────────────

export interface DependencyGraph {
  [name: string]: {
    version: string;
    type: "dependency" | "devDependency";
  };
}

export interface GraphNode {
  name: string;
  version: string;
  type: "dependency" | "devDependency";
  depth: number;
  blastRadius: number;
  isCritical: boolean;
  dependents: string[];
}

export interface EnhancedDependencyGraph {
  nodes: Record<string, GraphNode>;
  criticalNodes: string[];
  circularDependencies: string[][];
  totalDepth: number;
  summary: {
    totalNodes: number;
    criticalCount: number;
    maxDepth: number;
    avgBlastRadius: number;
  };
}

// ─── Breaking Change Prediction ───────────────────────────────────────────────

export interface BreakingChangePrediction {
  packageName: string;
  currentVersion: string;
  latestVersion: string;
  versionDelta: VersionDelta;
  impactSeverity: ImpactSeverity;
  likelyBreakingChanges: string[];
  affectedAreas: string[];
  confidenceScore: number; // 0–100
  reasoning: string;
}

export interface VersionDelta {
  current: string;
  latest: string;
  majorBump: boolean;
  minorBump: boolean;
  patchBump: boolean;
  versionsOutdated: number;
}

// ─── Upgrade Plan ─────────────────────────────────────────────────────────────

export type UpgradeAction = "safe-upgrade" | "cautious-upgrade" | "hold" | "replace";

export interface UpgradeStep {
  order: number;
  packageName: string;
  currentVersion: string;
  targetVersion: string;
  action: UpgradeAction;
  riskScore: number;
  warnings: string[];
  rollbackCommand: string;
  upgradeCommand: string;
  reasoning: string;
}

export interface UpgradePlan {
  projectPath: string;
  generatedAt: string;
  totalPackages: number;
  estimatedRisk: RiskLevel;
  steps: UpgradeStep[];
  summary: {
    safeUpgrades: number;
    cautiousUpgrades: number;
    holdPackages: number;
    replacePackages: number;
  };
  executionOrder: string[];
  globalWarnings: string[];
  rollbackStrategy: string;
}

// ─── AI Explanation ───────────────────────────────────────────────────────────

export interface DependencyExplanation {
  packageName: string;
  verdict: string;
  riskSummary: string;
  signals: ExplanationSignal[];
  ecosystemContext: string;
  maintenanceAssessment: string;
  recommendation: string;
}

export interface ExplanationSignal {
  label: string;
  value: string;
  impact: "positive" | "neutral" | "negative";
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

export interface Vulnerability {
  id?: string;
  version?: string;
  summary: string;
  details: string;
  affected: any;
  references: any;
  severity: string;
  packageName?: string;
}

// ─── System Health ────────────────────────────────────────────────────────────

export interface RepoHealthScore {
  healthScore: number;
  healthLevel: HealthLevel;
  summary: string;
  breakdown: {
    avgRiskScore: number;
    outdatedRatio: number;
    criticalCount: number;
    maintenanceScore: number;
  };
  topIssues: string[];
}

// ─── Analysis Results ─────────────────────────────────────────────────────────

export interface AnalysisResult {
  projectPath: string;
  analyzedAt: string;
  totalDependencies: number;
  dependencies: DependencyRisk[];
  dependencyGraph: DependencyGraph;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    averageRiskScore: number;
  };
}

export interface EnhancedAnalysisResult extends AnalysisResult {
  healthScore: RepoHealthScore;
  criticalIssues: string[];
  riskGroups: {
    critical: DependencyRisk[];
    high: DependencyRisk[];
    medium: DependencyRisk[];
    low: DependencyRisk[];
  };
}
