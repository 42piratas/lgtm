import { getDomain } from "tldts";
import { fetchUrl, hostOf, type FetchedResponse } from "./http.js";
import { withRetry, RETRY_ATTEMPTS } from "./retry.js";

// A black-box runner only ever "sees" whatever HTML comes back on the wire.
// Two ways that HTML can lie about being the site under audit:
//
//   1. An auth gate intercepted the request and redirected cross-origin
//      (Cloudflare Access, Vercel SSO, Okta, Auth0, ...). Grading that
//      response grades the identity provider's login page, not the site.
//   2. The response is a non-2xx/3xx status (429 from bot protection, 5xx
//      from an upstream outage, ...). Absence of a clean response is not
//      evidence the site is clean — it means the runner never saw it.
//
// Every black-box runner must refuse to score in both cases: a loud runner
// status, never a silent "no findings".

const KNOWN_GATE_HOST_PATTERNS: RegExp[] = [
  /(^|\.)cloudflareaccess\.com$/i, // Cloudflare Access
  /(^|\.)vercel\.com$/i, // Vercel SSO (vercel.com/sso-api)
  /(^|\.)okta\.com$/i,
  /(^|\.)oktapreview\.com$/i,
  /(^|\.)okta-emea\.com$/i,
  /(^|\.)auth0\.com$/i,
];

export interface AuthGateCheck {
  gated: boolean;
  /** Human-readable reason, set whenever `gated` is true. */
  reason?: string;
}

/**
 * Same *site*, not same host. `example.com` → `www.example.com` is one of the
 * most common redirects on the web, and a scanner that calls it an auth gate
 * red-builds healthy projects — a gate that cries wolf gets switched off, and
 * then it protects nothing. So the comparison is on the registrable domain
 * (eTLD+1) via the public suffix list: any subdomain hop within the same
 * registrable domain (apex↔www, or any other) is the same site.
 *
 * tldts bundles the real PSL, so multi-label suffixes are handled correctly
 * (`foo.co.uk` and `bar.foo.co.uk` both → `foo.co.uk`; a naive "last two
 * labels" rule would wrongly read those as `co.uk`).
 *
 * Hosts with no registrable domain (localhost, bare IPs) return null from
 * getDomain — fall back to an exact hostname match for those.
 */
function sameSite(a: string, b: string): boolean {
  if (a === b) return true;
  const da = getDomain(a);
  const db = getDomain(b);
  if (da === null || db === null) return false; // localhost / IP → exact match only
  return da === db;
}

/**
 * Compare where a response actually landed against the host we asked for.
 *
 * A landing is only an auth gate if it's genuinely a *different site*:
 *   - same registrable domain (apex↔www, any subdomain hop) → NOT a gate
 *   - a known identity provider (Cloudflare Access, Vercel SSO, Okta,
 *     Auth0) → always a gate, regardless of anything else
 *   - any other registrable-domain change → treated as a gate
 *
 * Known limitation, stated plainly: a login page hosted on the site's *own*
 * registrable domain (e.g. example.com → sso.example.com) is not detected as
 * a gate by the domain check, and will be scored. The named-provider list is
 * what catches the common managed cases; a self-hosted same-domain IdP is a
 * gap. It's the deliberate trade for not red-building every apex→www site.
 */
export function detectAuthGate(expectedUrl: string, finalUrl: string): AuthGateCheck {
  const expected = hostOf(expectedUrl);
  const landed = hostOf(finalUrl);
  if (!landed || !expected) return { gated: false };

  // A known provider is a hard signal — check it before the same-site
  // shortcut, so a gate is never waved through on a domain technicality.
  if (KNOWN_GATE_HOST_PATTERNS.some((re) => re.test(landed))) {
    return {
      gated: true,
      reason: `redirected to a known auth gate (${landed}) instead of ${expected} — the target is access-gated; refusing to grade someone else's login page`,
    };
  }

  // apex↔www and every other same-registrable-domain hop is the same site.
  // (A bare http→https upgrade lands on the same host and is covered here too.)
  if (sameSite(expected, landed)) return { gated: false };

  return {
    gated: true,
    reason: `response came from ${landed}, a different site than the configured ${expected} (cross-site redirect, likely an auth gate) — refusing to score content from another origin`,
  };
}

/** Null when the status is fine (2xx/3xx); else the reason it isn't. */
export function badStatusReason(status: number): string | null {
  if (status >= 200 && status < 400) return null;
  return `HTTP ${status} — could not fetch the real page; findings are unknown, not absent`;
}

export interface ProbeResult {
  ok: boolean;
  /** Set whenever ok === false — always human-readable and loud. */
  note?: string;
  status?: number;
  finalUrl?: string;
  headers?: Record<string, string>;
}

/**
 * For runners that don't already do their own plain-HTTP fetch (a11y,
 * lighthouse, zap): one lightweight request against baseUrl to catch an
 * auth-gate redirect or a bad status before spending browser/docker time on
 * content that was never the actual site.
 */
/**
 * Fetch the target, retrying only transport-level failures (DNS blip,
 * connection reset, timeout) — exactly the transient case the retry policy
 * exists for. A *status* the server chose to send us (429, 5xx) is NOT
 * retried: that's a definite answer, and hammering a rate-limiter is both
 * useless and rude. See util/retry.ts. Shared by headers/cookies (which score
 * this very response) and probeTarget (which guards the heavier runners).
 */
export async function fetchTarget(
  url: string,
  timeoutMs = 30_000,
): Promise<{ res?: FetchedResponse; err?: Error }> {
  return withRetry(
    async (): Promise<{ res?: FetchedResponse; err?: Error }> => {
      try {
        return { res: await fetchUrl(url, { timeoutMs }) };
      } catch (err) {
        return { err: err as Error };
      }
    },
    (r) => r.err !== undefined,
  );
}

/** How a failed fetchTarget should be phrased in a runner note. */
export function unreachableNote(url: string, err?: Error): string {
  return `could not reach ${url} after ${RETRY_ATTEMPTS + 1} attempts: ${err?.message}`;
}

export async function probeTarget(baseUrl: string): Promise<ProbeResult> {
  const attempt = await fetchTarget(baseUrl, 20_000);
  if (!attempt.res) {
    return { ok: false, note: unreachableNote(baseUrl, attempt.err) };
  }
  const res = attempt.res;

  const gate = detectAuthGate(baseUrl, res.finalUrl);
  if (gate.gated) {
    return { ok: false, note: `refusing to score — ${gate.reason}`, status: res.status, finalUrl: res.finalUrl };
  }

  const bad = badStatusReason(res.status);
  if (bad) {
    return { ok: false, note: `refusing to score — ${bad} (${res.finalUrl})`, status: res.status, finalUrl: res.finalUrl };
  }

  return { ok: true, status: res.status, finalUrl: res.finalUrl, headers: res.headers };
}
