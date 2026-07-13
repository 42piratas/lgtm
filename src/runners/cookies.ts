import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { fetchUrl, isLocalhostUrl } from "../util/http.js";
import { detectAuthGate, badStatusReason } from "../util/authgate.js";

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
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;
    const https = url.startsWith("https://") && !isLocalhostUrl(url);

    let res;
    try {
      res = await fetchUrl(url, { timeoutMs: 30_000 });
    } catch (err) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `fetch failed: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
      };
    }

    // Same rule as headers: an auth-gate redirect or a non-2xx/3xx response
    // means we never actually saw the site's cookies — "no cookies found"
    // would silently misreport as "clean".
    const gate = detectAuthGate(url, res.finalUrl);
    if (gate.gated) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `refusing to score — ${gate.reason}`,
        findings,
        durationMs: Date.now() - start,
      };
    }
    const bad = badStatusReason(res.status);
    if (bad) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `refusing to score — ${bad}`,
        findings,
        durationMs: Date.now() - start,
      };
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

    if (findings.length === 0) {
      findings.push({
        id: "cookies-ok",
        title:
          cookies.length === 0
            ? "No cookies set on the base response"
            : "All cookies carry sound security attributes",
        severity: "info",
      });
    }

    return {
      runnerId: this.id,
      domain: this.domain,
      status: "ok",
      findings,
      durationMs: Date.now() - start,
      meta: { cookieCount: cookies.length },
    };
  },
};
