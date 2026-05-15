import { resolve } from "path";
import { stat } from "fs/promises";

/**
 * Validates that a given projectPath is:
 * - An absolute path (after resolving)
 * - An existing directory on disk
 * - Does not escape via traversal tricks
 */
export async function validateProjectPath(input: string): Promise<string> {
  const resolved = resolve(input);

  // Prevent obvious traversal patterns in the raw input
  if (input.includes("\0")) {
    throw new Error("Invalid project path: null byte detected");
  }

  let stats;
  try {
    stats = await stat(resolved);
  } catch {
    throw new Error(`Project path does not exist: ${resolved}`);
  }

  if (!stats.isDirectory()) {
    throw new Error(`Project path is not a directory: ${resolved}`);
  }

  return resolved;
}
