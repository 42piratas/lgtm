// Resilience policy for the whole harness. Stated once, here, because the
// scoring layer now hard-fails the run on any runner error (42L-973) — which
// is right for "the scanner couldn't see the site", and wrong for "the
// network hiccuped for 300ms". Failing someone's CI for a blip is how a gate
// gets disabled, and a disabled gate protects nothing.
//
// The policy, in three buckets:
//
//   SKIP  (no coverage, does not fail the run)
//         A capability is absent by configuration, not broken: Docker not
//         installed/running, no repoPath for a white-box runner, no TLS on an
//         http target, no auth session configured. Nothing was attempted, and
//         nothing is claimed. Loudly reported as a coverage hole.
//
//   RETRY (bounded: 2 attempts after the first, exponential backoff)
//         The attempt failed in a way that is plausibly transient and
//         self-correcting: a network error reaching the target, an image-pull
//         timeout, a killed container, a registry/ruleset-fetch blip. We try
//         again before drawing any conclusion.
//
//   ERROR (fails the run)
//         Everything that survives the retries, plus anything definitively
//         conclusive-but-bad: an auth gate, a non-2xx/3xx status, a tool that
//         ran and produced unparseable output. The scanner did not see the
//         site and must not pretend otherwise.
//
// Deliberately NOT retried: an HTTP status the server *chose* to send us
// (429/403 from bot protection, 5xx). That is a definite answer, and hammering
// a rate-limiter is both useless and rude. It errors on the first response.

export const RETRY_ATTEMPTS = 2; // retries *after* the initial attempt
const BASE_BACKOFF_MS = 500;

const TRANSIENT_PATTERNS: RegExp[] = [
  /\bi\/o timeout\b/i,
  /\bdial tcp\b/i,
  /\bconnection reset\b/i,
  /\bconnection refused\b/i,
  /\btls handshake timeout\b/i,
  /\btemporary failure\b/i,
  /\btimeout exceeded\b/i,
  /\btoomanyrequests\b/i, // registry pull throttling
  /\bnet\/http\b/i,
  /\bEOF\b/,
  /\bunexpected end of/i,
  /\bregistry\b.*\b(unavailable|timeout)\b/i,
  /\b50[0234]\s+(internal|bad gateway|service unavailable|gateway timeout)\b/i,
];

/**
 * True when a failure looks transient and self-correcting — worth one more
 * try before we declare the runner errored.
 *
 * Note what is NOT here: "manifest unknown" / "not found" (a wrong image tag
 * is permanent — retrying just makes a wrong config take 3x as long to fail),
 * and anything about parsing a tool's output (the tool ran; it just said
 * something we couldn't read).
 */
export function isTransientFailure(text: string): boolean {
  return TRANSIENT_PATTERNS.some((re) => re.test(text));
}

/**
 * Run `fn` up to 1 + RETRY_ATTEMPTS times, retrying only while `shouldRetry`
 * says the result is transient. Returns the last result either way — the
 * caller still decides what a final failure means.
 */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  shouldRetry: (result: T) => boolean,
  opts: { attempts?: number; onRetry?: (attempt: number, result: T) => void } = {},
): Promise<T> {
  const attempts = opts.attempts ?? RETRY_ATTEMPTS;
  let last = await fn(0);
  for (let i = 1; i <= attempts; i++) {
    if (!shouldRetry(last)) return last;
    opts.onRetry?.(i, last);
    await sleep(BASE_BACKOFF_MS * 2 ** (i - 1)); // 500ms, 1000ms
    last = await fn(i);
  }
  return last;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
