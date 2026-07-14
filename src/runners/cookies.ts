import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { isLocalhostUrl } from "../util/http.js";
import {
  detectAuthGate,
  badStatusReason,
  fetchTarget,
  unreachableNote,
} from "../util/authgate.js";

// Cookie hygiene + basic CSRF signal, parsed from raw Set-Cookie lines.
// Aligned with OWASP ASVS 3.4 (cookie-based session management).

interface ParsedCookie {
  name: string;
  attrs: Set<string>; // lowercased attribute keywords
  sameSite?: string;
}

function parseCookie(line: string): ParsedCookie {
  const parts = line.split(";").map((p) => p.trim());
  const first = parts[0] ?? "";
  const name = first.split("=")[0] ?? "";
  const attrs = new Set<string>();
  let sameSite: string | undefined;
  for (const p of parts.slice(1)) {
    const lc = p.toLowerCase();
    if (lc.startsWith("samesite=")) sameSite = lc.split("=")[1];
    attrs.add(lc.split("=")[0] ?? lc);
  }
  return { name, attrs, sameSite };
}

const SESSION_HINT = /(sess|sid|auth|token|jwt|sb-|supabase|next-auth|csrf)/i;

export const cookiesRunner: Runner = {
  id: "cookies",
  domain: "privacy",
  title: "Cookie hygiene & CSRF signal",
  requires: { target: true },

  /**
   * A site that legitimately sets no cookies has nothing to get wrong, so an
   * empty cookie jar IS a clean result here — but only once we have actually
   * read a response. Never seeing one is the case that must not pass.
   */
  sufficient(cov: Coverage): string | null {
    return cov.data.responded ? null : "no response was read from the target";
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;
    const https = url.startsWith("https://") && !isLocalhostUrl(url);

    // Transport failures get a bounded retry before we conclude anything (see
    // util/retry.ts); a bad *status* does not — that's a definite answer.
    const attempt = await fetchTarget(url);
    if (!attempt.res) {
      return { kind: "failed", note: unreachableNote(url, attempt.err) };
    }
    const res = attempt.res;

    // Same rule as headers: an auth-gate redirect or a non-2xx/3xx response
    // means we never actually saw the site's cookies — "no cookies found"
    // would silently misreport as "clean".
    const gate = detectAuthGate(url, res.finalUrl);
    if (gate.gated) {
      return { kind: "failed", note: `refusing to score — ${gate.reason}` };
    }
    const bad = badStatusReason(res.status);
    if (bad) {
      return { kind: "failed", note: `refusing to score — ${bad}` };
    }

    const cookies = res.setCookie.map(parseCookie);

    for (const c of cookies) {
      const sensitive = SESSION_HINT.test(c.name);
      if (!c.attrs.has("httponly") && sensitive) {
        findings.push({
          id: `cookie-httponly-${c.name}`,
          title: `Session cookie '${c.name}' lacks HttpOnly`,
          severity: "high",
          standard: "OWASP ASVS 3.4.2",
          location: res.finalUrl,
          remediation: "Set HttpOnly on session/auth cookies.",
        });
      }
      if (!c.attrs.has("secure") && https) {
        findings.push({
          id: `cookie-secure-${c.name}`,
          title: `Cookie '${c.name}' lacks Secure over HTTPS`,
          severity: sensitive ? "high" : "medium",
          standard: "OWASP ASVS 3.4.1",
          location: res.finalUrl,
          remediation: "Set the Secure attribute on cookies served over HTTPS.",
        });
      }
      if (!c.sameSite) {
        findings.push({
          id: `cookie-samesite-${c.name}`,
          title: `Cookie '${c.name}' has no SameSite attribute`,
          severity: sensitive ? "medium" : "low",
          standard: "OWASP ASVS 3.4.3",
          location: res.finalUrl,
          remediation:
            "Set SameSite=Lax (or Strict) unless a cross-site cookie is required.",
        });
      } else if (c.sameSite === "none" && !c.attrs.has("secure")) {
        findings.push({
          id: `cookie-samesite-none-insecure-${c.name}`,
          title: `Cookie '${c.name}' is SameSite=None without Secure`,
          severity: "high",
          standard: "OWASP ASVS 3.4.3",
          location: res.finalUrl,
          remediation: "SameSite=None requires the Secure attribute.",
        });
      }
    }

    // CSRF signal: a session cookie present but no anti-CSRF token cookie/header.
    const hasSession = cookies.some((c) => SESSION_HINT.test(c.name));
    const hasCsrf =
      cookies.some((c) => /csrf|xsrf/i.test(c.name)) ||
      "x-csrf-token" in res.headers;
    if (hasSession && !hasCsrf) {
      findings.push({
        id: "csrf-signal",
        title:
          "Session cookie present but no CSRF token detected (verify state-changing routes use SameSite or tokens)",
        severity: "low",
        standard: "OWASP ASVS 4.2.2",
        location: res.finalUrl,
        remediation:
          "Confirm state-changing requests are CSRF-protected (SameSite=Lax/Strict cookies or a synchronizer/double-submit token).",
      });
    }

    return {
      kind: "observed",
      findings,
      coverage: {
        trail: [
          `GET ${url} → ${res.status} (${res.finalUrl})`,
          cookies.length === 0
            ? "response set no cookies"
            : `inspected ${cookies.length} cookie${cookies.length === 1 ? "" : "s"}: ${cookies.map((c) => c.name).join(", ")}`,
        ],
        data: { responded: true, status: res.status, cookies: cookies.length },
        provenance: "Set-Cookie headers of the base URL response",
      },
      meta: { cookieCount: cookies.length },
    };
  },
};
