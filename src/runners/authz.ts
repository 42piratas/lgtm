import { chromium } from "playwright";
import { existsSync } from "node:fs";
import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";

// Authenticated-access checks. Drives two browser contexts — one carrying the
// operator's session (storageState), one anonymous — and compares:
//   1. session actually authenticates (authed routes don't bounce to login);
//   2. authed routes are NOT reachable anonymously (missing-guard signal);
//   3. authed HTML responses are not cacheable (no-store).
// This is a smoke test for broken access control, not a full authz audit.

const LOGIN_HINT = /(login|signin|sign-in|auth|\/authenticate)/i;

export const authzRunner: Runner = {
  id: "authz",
  domain: "authz",
  title: "Authenticated access & session hygiene",
  requires: { target: true, browser: true },

  /**
   * "Protected routes enforce auth" is a claim about routes. Probe none, and
   * there is no claim to make — the old runner said it anyway, on a site with
   * no routes configured. And a route whose probe never landed tells us nothing
   * about whether it is reachable anonymously, which is the one thing this
   * runner exists to find out.
   */
  sufficient(cov: Coverage): string | null {
    const configured = Number(cov.data.routesConfigured ?? 0);
    const probed = Number(cov.data.routesProbed ?? 0);
    const failed = Number(cov.data.probesFailed ?? 0);
    // Order matters: a route that was configured but never loaded must be
    // reported as unverified, not as "you configured no routes" — the operator
    // would go looking in the wrong place.
    if (failed > 0) {
      return `${failed} probe${failed === 1 ? "" : "s"} never landed — ${configured - probed} route${configured - probed === 1 ? "" : "s"} not verified`;
    }
    if (configured === 0) {
      return "no protected routes are configured — add app routes to the site config to exercise access control";
    }
    if (probed === 0) {
      return "no protected route was successfully probed";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];

    if (ctx.site.auth.type !== "storageState") {
      // The operator declared this site has no authenticated surface. There is
      // no access control to audit — nothing was missed.
      return {
        kind: "notApplicable",
        note: "no authenticated session configured for this site",
      };
    }
    if (!existsSync(ctx.site.auth.path)) {
      // The site DOES have an authenticated surface; we just have no session to
      // reach it with. That surface went unaudited — a hole, not a non-issue.
      return {
        kind: "unavailable",
        note: "auth storageState file missing — run `lgtm auth` to capture one; the authenticated surface was not audited",
      };
    }

    // Routes beyond the base URL are the candidate protected surfaces.
    const protectedUrls = ctx.urls.filter((u) => u !== ctx.run.baseUrl);
    const trail: string[] = [];

    const browser = await chromium.launch({ headless: true });
    try {
      const authed = await browser.newContext({
        storageState: ctx.site.auth.path,
        ignoreHTTPSErrors: true,
      });
      const anon = await browser.newContext({ ignoreHTTPSErrors: true });

      let sessionWorks = false;

      // A route whose navigation blew up (timeout, redirect loop, connection
      // reset — all realistic against a real WAF) was NEVER CHECKED. Swallowing
      // that, as this runner used to, meant the route produced no finding at
      // all — not open, not blocked, not even a note — and then `authz-ok`
      // still fired: "Protected routes enforce auth." A definite claim about a
      // route nobody looked at, in the one runner whose entire job is catching
      // broken access control. That is the exact bug this whole change set
      // exists to kill. Unchecked is not "safe": it is unknown, and unknown
      // fails the run.
      const navFailures: Array<{ url: string; phase: string; message: string }> = [];
      // A route only counts as probed when BOTH views landed: the anonymous
      // probe is what detects a missing guard, the authed one is what proves the
      // route exists behind the session. One without the other is half a check.
      const landedAuthed = new Set<string>();
      const landedAnon = new Set<string>();

      for (const url of protectedUrls) {
        // (1)+(3): authed view.
        const ap = await authed.newPage();
        try {
          const resp = await ap.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
          const landed = ap.url();
          const bounced = LOGIN_HINT.test(landed) && !LOGIN_HINT.test(url);
          if (!bounced) sessionWorks = true;
          else {
            findings.push({
              id: `authz-session-bounce`,
              title: `Authed session bounced to login at ${url} (session may be expired/invalid)`,
              severity: "info",
              location: landed,
              remediation: "Re-capture the session with `lgtm auth`.",
            });
          }
          // (3) cacheability of an authed HTML response.
          const cc = resp?.headers()["cache-control"] ?? "";
          if (!bounced && !/no-store/.test(cc)) {
            findings.push({
              id: `authz-cache-${url}`,
              title: `Authenticated response is cacheable (Cache-Control: ${cc || "unset"})`,
              severity: "low",
              standard: "OWASP ASVS 8.3.4",
              location: url,
              remediation:
                "Send Cache-Control: no-store on authenticated responses to prevent shared-cache leakage.",
            });
          }
          landedAuthed.add(url);
        } catch (err) {
          navFailures.push({
            url,
            phase: "authenticated",
            message: (err as Error).message,
          });
        } finally {
          await ap.close().catch(() => {});
        }

        // (2): anonymous access to the same protected route.
        const np = await anon.newPage();
        try {
          const resp = await np.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
          const landed = np.url();
          const status = resp?.status() ?? 0;
          const redirectedToLogin = LOGIN_HINT.test(landed) && !LOGIN_HINT.test(url);
          const blocked = status === 401 || status === 403 || redirectedToLogin;
          if (!blocked && status >= 200 && status < 300) {
            findings.push({
              id: `authz-open-${url}`,
              title: `Protected route reachable anonymously (HTTP ${status}, no login redirect): ${url}`,
              severity: "high",
              standard: "OWASP Top 10 A01 (Broken Access Control)",
              location: url,
              remediation:
                "Enforce authentication server-side on this route; do not rely on client-side gating.",
            });
          }
          landedAnon.add(url);
          trail.push(
            `probed ${url} anonymously — HTTP ${status}${blocked ? " (blocked)" : " (reachable)"}`,
          );
        } catch (err) {
          // This is the load-bearing one: the anonymous probe is what detects
          // broken access control. If it never landed, we know NOTHING about
          // whether this route is reachable without a session.
          navFailures.push({
            url,
            phase: "anonymous",
            message: (err as Error).message,
          });
        } finally {
          await np.close().catch(() => {});
        }
      }

      if (protectedUrls.length > 0 && !sessionWorks) {
        findings.unshift({
          id: "authz-session-dead",
          title:
            "Configured session did not authenticate any protected route — access-control checks are unreliable",
          severity: "info",
          remediation: "Re-capture the session with `lgtm auth`.",
        });
      }

      // Every unchecked route gets its own visible finding — never silently
      // dropped. Any genuinely-open route found before the failure is still
      // reported alongside it: a nav failure removes certainty, it doesn't
      // erase evidence. The coverage numbers below are what stop the run
      // passing on a half-finished access-control audit.
      for (const f of navFailures) {
        findings.push({
          id: `authz-unchecked-${f.phase}-${f.url}`,
          title: `Access control NOT verified for ${f.url} — the ${f.phase} probe failed to load it (${f.message.slice(0, 120)})`,
          severity: "info",
          needsReview: true,
          standard: "OWASP Top 10 A01 (Broken Access Control) — unverified",
          location: f.url,
          remediation:
            "This route was never actually checked: the result is unknown, not safe. Re-run once the target is reachable (a timeout/reset here is often a WAF rate-limiting the scanner).",
        });
        trail.push(`FAILED ${f.phase} probe of ${f.url}`);
      }

      const routesProbed = [...landedAnon].filter((u) => landedAuthed.has(u)).length;

      return {
        kind: "observed",
        findings,
        coverage: {
          trail,
          data: {
            routesConfigured: protectedUrls.length,
            routesProbed,
            probesFailed: navFailures.length,
            sessionWorks,
          },
          provenance: "authenticated + anonymous navigation of each configured route",
        },
        meta: { protectedRoutes: protectedUrls.length, sessionWorks },
      };
    } catch (err) {
      return {
        kind: "failed",
        note: `browser session failed: ${(err as Error).message}`,
      };
    } finally {
      await browser.close().catch(() => {});
    }
  },
};
