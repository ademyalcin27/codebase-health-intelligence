import { z } from 'zod';
import { getVulnerabilities } from '../core/osv.js';
import { validateProjectPath } from '../lib/validate-path.js';

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().describe('The path to the project to analyze.'),
});

export async function checkKnownVulnerabilitiesTool(
  input: z.infer<typeof checkKnownVulnerabilitiesSchema>
) {
  const { projectPath } = input;
  await validateProjectPath(projectPath);
  return getVulnerabilities(projectPath);
}
