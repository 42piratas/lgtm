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

// Security-header expectations, aligned with the OWASP Secure Headers Project
// and Mozilla Observatory. Each check is evaluated against the base URL's
// response. Missing/weak → a finding; present-and-strong → an info pass-note.

interface HeaderCheck {
  id: string;
  header: string;
  severity: Finding["severity"];
  standard: string;
  remediation: string;
  /** Return null if OK, else a short reason the value is weak/missing. */
  evaluate: (value: string | undefined, ctx: { https: boolean }) => string | null;
}

const CHECKS: HeaderCheck[] = [
  {
    id: "csp",
    header: "content-security-policy",
    severity: "high",
    standard: "OWASP Secure Headers; CSP Level 3",
    remediation:
      "Set a Content-Security-Policy. Avoid 'unsafe-inline'/'unsafe-eval'; prefer nonces/hashes and a strict default-src.",
    evaluate: (v) => {
      if (!v) return "no Content-Security-Policy header";
      const lc = v.toLowerCase();
      const weak: string[] = [];
      if (lc.includes("unsafe-inline")) weak.push("uses 'unsafe-inline'");
      if (lc.includes("unsafe-eval")) weak.push("uses 'unsafe-eval'");
      if (!lc.includes("default-src") && !lc.includes("script-src"))
        weak.push("no default-src/script-src directive");
      if (lc.includes("script-src") && lc.match(/script-src[^;]*\*/))
        weak.push("wildcard in script-src");
      return weak.length ? weak.join("; ") : null;
    },
  },
  {
    id: "hsts",
    header: "strict-transport-security",
    severity: "high",
    standard: "RFC 6797; OWASP Secure Headers",
    remediation:
      "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (min max-age 31536000).",
    evaluate: (v, { https }) => {
      if (!https) return null; // HSTS is meaningless over http (localhost dev)
      if (!v) return "no Strict-Transport-Security header";
      const m = v.match(/max-age=(\d+)/i);
      if (!m || !m[1]) return "no max-age directive";
      if (Number(m[1]) < 31536000) return `max-age ${m[1]} < 1 year`;
      return null;
    },
  },
  {
    id: "x-content-type-options",
    header: "x-content-type-options",
    severity: "medium",
    standard: "OWASP Secure Headers",
    remediation: "Set X-Content-Type-Options: nosniff.",
    evaluate: (v) =>
      v?.toLowerCase().includes("nosniff") ? null : "missing or not 'nosniff'",
  },
  {
    id: "x-frame-options",
    header: "x-frame-options",
    severity: "medium",
    standard: "OWASP Secure Headers (clickjacking)",
    remediation:
      "Set X-Frame-Options: DENY, or a CSP frame-ancestors 'none'/'self' directive.",
    evaluate: (v) => {
      // CSP frame-ancestors supersedes XFO; the runner cross-checks below.
      if (!v) return "no X-Frame-Options header";
      const lc = v.toLowerCase();
      if (lc.includes("deny") || lc.includes("sameorigin")) return null;
      return `weak value '${v}'`;
    },
  },
  {
    id: "referrer-policy",
    header: "referrer-policy",
    severity: "low",
    standard: "OWASP Secure Headers",
    remediation:
      "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    evaluate: (v) => (v ? null : "no Referrer-Policy header"),
  },
  {
    id: "permissions-policy",
    header: "permissions-policy",
    severity: "low",
    standard: "W3C Permissions Policy",
    remediation:
      "Set Permissions-Policy to disable unused features, e.g. geolocation=(), camera=(), microphone=().",
    evaluate: (v) => (v ? null : "no Permissions-Policy header"),
  },
  {
    id: "coop",
    header: "cross-origin-opener-policy",
    severity: "low",
    standard: "HTML spec; cross-origin isolation",
    remediation: "Set Cross-Origin-Opener-Policy: same-origin.",
    evaluate: (v) =>
      v?.toLowerCase().includes("same-origin") ? null : "missing/weak COOP",
  },
];

// Headers that leak stack detail — presence is the finding.
const LEAKY = ["server", "x-powered-by", "x-aspnet-version"];

export const headersRunner: Runner = {
  id: "headers",
  domain: "security",
  title: "Security headers",
  requires: { target: true },

  /**
   * The headers verdict rests on one response. If we never read one, or the
   * check list somehow evaluated nothing, "no findings" says nothing about
   * the site's headers.
   */
  sufficient(cov: Coverage): string | null {
    if (!cov.data.responded) return "no response was read from the target";
    if (Number(cov.data.checksEvaluated ?? 0) === 0) {
      return "no header checks were evaluated";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;
    // Transport failures get a bounded retry before we conclude anything (see
    // util/retry.ts); a bad *status* does not — that's a definite answer.
    const attempt = await fetchTarget(url);
    if (!attempt.res) {
      return { kind: "failed", note: unreachableNote(url, attempt.err) };
    }
    const res = attempt.res;

    // Refuse to score whatever landed if it isn't actually the configured
    // target: an auth-gate redirect (Cloudflare Access, Vercel SSO, Okta,
    // Auth0, ...) or a non-2xx/3xx response (429 bot-protection, 5xx, ...).
    // Grading either would report someone else's page, or report "no
    // headers" for a request that was never let through.
    const gate = detectAuthGate(url, res.finalUrl);
    if (gate.gated) {
      return {
        kind: "failed",
        note: `refusing to score — ${gate.reason}`,
        meta: { finalUrl: res.finalUrl, status: res.status },
      };
    }
    const bad = badStatusReason(res.status);
    if (bad) {
      return {
        kind: "failed",
        note: `refusing to score — ${bad}`,
        meta: { finalUrl: res.finalUrl, status: res.status },
      };
    }

    const https = url.startsWith("https://") && !isLocalhostUrl(url);
    const h = res.headers;
    const csp = h["content-security-policy"] ?? "";
    const cspFrameAncestors = /frame-ancestors/i.test(csp);

    let checksEvaluated = 0;
    for (const c of CHECKS) {
      checksEvaluated++;
      // XFO is satisfied by a CSP frame-ancestors directive.
      if (c.id === "x-frame-options" && cspFrameAncestors && !h[c.header]) {
        continue;
      }
      const reason = c.evaluate(h[c.header], { https });
      if (reason) {
        findings.push({
          id: c.id,
          title: `${c.header}: ${reason}`,
          severity: c.severity,
          standard: c.standard,
          location: res.finalUrl,
          remediation: c.remediation,
          evidence: h[c.header] ? `${c.header}: ${h[c.header]}` : undefined,
        });
      }
    }

    for (const leak of LEAKY) {
      if (h[leak]) {
        findings.push({
          id: `leak-${leak}`,
          title: `${leak} header leaks stack detail`,
          severity: "low",
          standard: "OWASP ASVS 14.4.4 (information leakage)",
          location: res.finalUrl,
          remediation: `Remove or blank the ${leak} response header.`,
          evidence: `${leak}: ${h[leak]}`,
        });
      }
    }

    // http:// on a non-local target is itself a finding.
    if (url.startsWith("http://") && !isLocalhostUrl(url)) {
      findings.push({
        id: "no-tls",
        title: "Target served over plaintext HTTP",
        severity: "high",
        standard: "OWASP ASVS 9.1",
        location: url,
        remediation: "Serve exclusively over HTTPS and redirect http→https.",
      });
    }

    return {
      kind: "observed",
      findings,
      coverage: {
        trail: [
          `GET ${url} → ${res.status} (${res.finalUrl})`,
          `evaluated ${checksEvaluated} header check${checksEvaluated === 1 ? "" : "s"} + ${LEAKY.length} leak checks`,
        ],
        data: {
          responded: true,
          status: res.status,
          checksEvaluated,
          headersRead: Object.keys(h).length,
        },
        provenance: "response headers of the base URL",
      },
      meta: { finalUrl: res.finalUrl, status: res.status },
    };
  },
};
