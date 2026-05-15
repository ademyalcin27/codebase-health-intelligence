import { logger } from "./logger.js";

export function validateEnv(): void {
  if (!process.env.GITHUB_TOKEN) {
    logger.warn(
      "GITHUB_TOKEN is not set. GitHub API requests will be rate-limited to 60/hour. " +
      "Set GITHUB_TOKEN in your .env file or environment to raise this to 5000/hour."
    );
  }

  const logLevel = process.env.LOG_LEVEL;
  if (logLevel && !["debug", "info", "warn", "error"].includes(logLevel)) {
    logger.warn("Invalid LOG_LEVEL value — must be debug | info | warn | error. Defaulting to info.", {
      received: logLevel,
    });
  }
}
