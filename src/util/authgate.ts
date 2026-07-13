import { fetchUrl, hostOf } from "./http.js";

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
 * Compare where a response actually landed against the host we asked for.
 * Any cross-origin landing is refused — named gates get a specific reason,
 * anything else still gets a generic "not the configured host" refusal.
 */
export function detectAuthGate(expectedUrl: string, finalUrl: string): AuthGateCheck {
  const expected = hostOf(expectedUrl);
  const landed = hostOf(finalUrl);
  if (!landed || !expected || landed === expected) return { gated: false };

  const knownGate = KNOWN_GATE_HOST_PATTERNS.some((re) => re.test(landed));
  if (knownGate) {
    return {
      gated: true,
      reason: `redirected to a known auth gate (${landed}) instead of ${expected} — the target is access-gated; refusing to grade someone else's login page`,
    };
  }
  return {
    gated: true,
    reason: `response came from ${landed}, not the configured host ${expected} (cross-origin redirect, likely an auth gate) — refusing to score content from a different origin`,
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
export async function probeTarget(baseUrl: string): Promise<ProbeResult> {
  let res;
  try {
    res = await fetchUrl(baseUrl, { timeoutMs: 20_000 });
  } catch (err) {
    return { ok: false, note: `could not reach ${baseUrl}: ${(err as Error).message}` };
  }

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
