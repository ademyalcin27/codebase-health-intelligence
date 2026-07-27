import { z } from "zod";
import { queryOsv } from "../core/osv.js";
import { promises as fs } from "fs";
import path from "path";

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().describe("The path to the project to analyze."),
});

export async function checkKnownVulnerabilities(input: z.infer<typeof checkKnownVulnerabilitiesSchema>) {
  const packageJsonPath = path.join(input.projectPath, "package.json");
  const packageLockJsonPath = path.join(input.projectPath, "package-lock.json");

  const [packageJsonContent, packageLockJsonContent] = await Promise.all([
    fs.readFile(packageJsonPath, "utf-8"),
    fs.readFile(packageLockJsonPath, "utf-8"),
  ]);

  const packageJson = JSON.parse(packageJsonContent);
  const packageLockJson = JSON.parse(packageLockJsonContent);

  const dependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  const packagesToScan = Object.keys(dependencies).map((name) => ({
    name,
    version: packageLockJson.packages[`node_modules/${name}`]?.version ?? dependencies[name],
  }));

  const vulnerabilities = await queryOsv(packagesToScan);

  const groupedBySeverity = vulnerabilities.reduce((acc: Record<string, any[]>, vuln) => {
    const severity = vuln.severity || "unknown";
    if (!acc[severity]) {
      acc[severity] = [];
    }
    acc[severity].push(vuln);
    return acc;
  }, {} as Record<string, any[]>);

  return {
    vulnerabilities: groupedBySeverity,
  };
}
