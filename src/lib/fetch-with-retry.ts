import fetch, { type RequestInit, type Response } from "node-fetch";
import { logger } from "./logger.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 500;

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string
  ) {
    super(`HTTP ${status} from ${url}`);
    this.name = "HttpError";
  }
}

export class TimeoutError extends Error {
  constructor(public readonly url: string) {
    super(`Request timed out: ${url}`);
    this.name = "TimeoutError";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryable(err: unknown, status?: number): boolean {
  if (err instanceof TimeoutError) return true;
  if (status && (status === 429 || status >= 500)) return true;
  return false;
}

export async function fetchWithRetry(
  url: string,
  options: RequestInit & { timeoutMs?: number } = {}
): Promise<Response> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...fetchOptions } = options;
  let lastError: unknown;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...fetchOptions,
        signal: controller.signal as RequestInit["signal"],
      });

      clearTimeout(timer);

      // Retry on rate-limit with Retry-After header
      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get("retry-after") ?? "5", 10);
        const delay = Math.max(retryAfter * 1000, RETRY_BASE_DELAY_MS * attempt);
        logger.warn("Rate limited", { url, attempt, retryAfterMs: delay });
        if (attempt < MAX_RETRIES) {
          await sleep(delay);
          continue;
        }
        throw new HttpError(429, url);
      }

      if (response.status >= 500 && attempt < MAX_RETRIES) {
        const delay = RETRY_BASE_DELAY_MS * 2 ** (attempt - 1);
        logger.warn("Server error, retrying", { url, status: response.status, attempt, delayMs: delay });
        await sleep(delay);
        lastError = new HttpError(response.status, url);
        continue;
      }

      return response;
    } catch (err: unknown) {
      clearTimeout(timer);

      const isAbort =
        err instanceof Error &&
        (err.name === "AbortError" || err.message.includes("aborted"));

      const wrapped = isAbort ? new TimeoutError(url) : err;

      if (isRetryable(wrapped) && attempt < MAX_RETRIES) {
        const delay = RETRY_BASE_DELAY_MS * 2 ** (attempt - 1);
        logger.warn("Fetch failed, retrying", {
          url,
          attempt,
          error: wrapped instanceof Error ? wrapped.message : String(wrapped),
          delayMs: delay,
        });
        await sleep(delay);
        lastError = wrapped;
        continue;
      }

      throw wrapped;
    }
  }

  throw lastError ?? new Error(`Failed after ${MAX_RETRIES} attempts: ${url}`);
}
