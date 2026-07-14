import { chromium } from "playwright";
import { existsSync } from "node:fs";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";

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
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    if (ctx.site.auth.type !== "storageState") {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "skipped",
        note: "no authenticated session configured for this site",
        findings,
        durationMs: Date.now() - start,
      };
    }
    if (!existsSync(ctx.site.auth.path)) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "skipped",
        note: "auth storageState file missing — run `lgtm auth` to capture one",
        findings,
        durationMs: Date.now() - start,
      };
    }

    // Routes beyond the base URL are the candidate protected surfaces.
    const protectedUrls = ctx.urls.filter((u) => u !== ctx.run.baseUrl);
    if (protectedUrls.length === 0) {
      findings.push({
        id: "authz-no-routes",
        title:
          "No protected routes configured — add app routes to the site config to exercise access control",
        severity: "info",
      });
    }

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
      // dropped — and the runner errors, so the run cannot pass on a partial
      // access-control audit. Any genuinely-open route found before the failure
      // is still reported alongside it; a nav failure removes certainty, it
      // doesn't erase evidence.
      if (navFailures.length > 0) {
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
        }
        const routes = [...new Set(navFailures.map((f) => f.url))];
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          note: `could not verify access control on ${routes.length} of ${protectedUrls.length} protected route(s): ${routes.join(", ")} — findings unknown, not absent`,
          findings,
          durationMs: Date.now() - start,
          meta: { protectedRoutes: protectedUrls.length, sessionWorks, unchecked: routes.length },
        };
      }

      if (findings.filter((f) => f.severity !== "info").length === 0) {
        findings.push({
          id: "authz-ok",
          title: "Protected routes enforce auth; authed responses are non-cacheable",
          severity: "info",
        });
      }

      return {
        runnerId: this.id,
        domain: this.domain,
        status: "ok",
        findings,
        durationMs: Date.now() - start,
        meta: { protectedRoutes: protectedUrls.length, sessionWorks },
      };
    } catch (err) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `browser session failed: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
      };
    } finally {
      await browser.close().catch(() => {});
    }
  },
};
