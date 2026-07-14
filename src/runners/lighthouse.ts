import { launch } from "chrome-launcher";
import lighthouse from "lighthouse";
import { readFileSync, existsSync } from "node:fs";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { probeTarget } from "../util/authgate.js";

// Performance / best-practices / SEO via Lighthouse. Category scores below
// threshold become findings; the numbers land in report meta either way.
// Auth cookies (from storageState) are injected so authed routes score too.

const THRESHOLDS: Record<string, number> = {
  performance: 0.8,
  "best-practices": 0.9,
  seo: 0.9,
};

const SEVERITY_BY_SCORE = (score: number): Finding["severity"] =>
  score < 0.5 ? "medium" : "low";

function cookieHeaderFrom(storageStatePath: string, url: string): string | undefined {
  if (!existsSync(storageStatePath)) return undefined;
  try {
    const state = JSON.parse(readFileSync(storageStatePath, "utf8")) as {
      cookies?: Array<{ name: string; value: string; domain: string }>;
    };
    const host = new URL(url).hostname;
    const jar = (state.cookies ?? [])
      .filter((c) => host.endsWith(c.domain.replace(/^\./, "")))
      .map((c) => `${c.name}=${c.value}`);
    return jar.length ? jar.join("; ") : undefined;
  } catch {
    return undefined;
  }
}

export const lighthouseRunner: Runner = {
  id: "lighthouse",
  domain: "perf",
  title: "Lighthouse (perf / best-practices / SEO)",
  requires: { target: true, browser: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;

    // Refuse before spending a Chrome launch on content that isn't the site:
    // an auth-gate redirect or a non-2xx/3xx response.
    const probe = await probeTarget(url);
    if (!probe.ok) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: probe.note,
        findings,
        durationMs: Date.now() - start,
      };
    }

    const chrome = await launch({
      chromeFlags: ["--headless=new", "--no-sandbox", "--ignore-certificate-errors"],
    }).catch(() => null);
    if (!chrome) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: "could not launch Chrome for Lighthouse",
        findings,
        durationMs: Date.now() - start,
      };
    }

    const extraHeaders: Record<string, string> = {};
    if (ctx.site.auth.type === "storageState") {
      const cookie = cookieHeaderFrom(ctx.site.auth.path, url);
      if (cookie) extraHeaders["Cookie"] = cookie;
    }

    try {
      const runnerResult = await lighthouse(
        url,
        {
          port: chrome.port,
          output: "json",
          logLevel: "error",
          onlyCategories: ["performance", "best-practices", "seo"],
          extraHeaders: Object.keys(extraHeaders).length ? extraHeaders : undefined,
        } as never,
      );
      const lhr = runnerResult?.lhr;

      // Lighthouse's own contract is `Promise<RunnerResult | undefined>` — it can
      // resolve with nothing at all, without throwing. If we let that fall through,
      // zero categories get scored, zero findings are produced, and the empty-findings
      // branch below cheerfully reports "scores meet thresholds" for a scan that
      // measured nothing. Same lie as a crashed semgrep reporting a clean repo:
      // the result is unknown, not good.
      if (!lhr || !lhr.categories) {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          findings: [],
          note: "Lighthouse returned no report — the scan produced no data, so the scores are unknown, not passing.",
          durationMs: Date.now() - start,
        };
      }

      // A page that never rendered (NO_FCP, ERRORED_DOCUMENT_REQUEST,
      // PROTOCOL_TIMEOUT) does NOT come back empty — Lighthouse returns
      // `categories` present with every `score: null`, plus a `runtimeError`
      // nobody was reading. The `?? 0` below then turned "unmeasured" into
      // "measured zero", producing three `medium` findings that sail past the
      // default `failOn: "high"`: a dead page scored as a passing audit.
      const runtimeError = (lhr as { runtimeError?: { code?: string; message?: string } })
        .runtimeError;
      if (runtimeError?.code && runtimeError.code !== "NO_ERROR") {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          findings: [],
          note: `Lighthouse could not measure the page (${runtimeError.code}): ${runtimeError.message ?? "no detail"} — the scores are unknown, not passing.`,
          durationMs: Date.now() - start,
        };
      }

      // A category's score is null the moment ANY audit inside it is unscored —
      // Lighthouse's arithmeticMean returns null if a single item is null. So a
      // null category does NOT mean "the page wasn't measured"; it can equally
      // mean "one audit legitimately did not apply to this page" (no images →
      // no image-alt check). Refusing on every null category would red-build
      // healthy sites, which is how a gate ends up switched off.
      //
      // Lighthouse CI — Google's own build gate — draws the line where it
      // belongs: a `notApplicable` audit counts as a PASS, while an audit that
      // ran and produced nothing is a hard failure ("Audit did not produce a
      // value at all"). We do the same: look at WHY the category is unscored.
      // Errored audits mean the page was not measured → refuse. Merely
      // not-applicable ones are not a defect → score what was measured.
      const audits = (lhr as { audits?: Record<string, { scoreDisplayMode?: string; title?: string }> })
        .audits ?? {};
      const erroredIn = (cat: { auditRefs?: Array<{ id: string }> }): string[] =>
        (cat.auditRefs ?? [])
          .filter((ref) => audits[ref.id]?.scoreDisplayMode === "error")
          .map((ref) => audits[ref.id]?.title ?? ref.id);

      const unmeasured = Object.entries(lhr.categories)
        .map(([key, cat]) => ({ key, errored: erroredIn(cat as { auditRefs?: Array<{ id: string }> }) }))
        .filter((c) => c.errored.length > 0);
      if (unmeasured.length > 0) {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          findings: [],
          note: `Lighthouse audits errored, so ${unmeasured.map((c) => c.key).join(", ")} could not be measured — the scores are unknown, not passing: ${unmeasured.flatMap((c) => c.errored).slice(0, 3).join("; ")}`,
          durationMs: Date.now() - start,
        };
      }

      const scores: Record<string, number> = {};
      const notApplicable: string[] = [];
      {
        for (const [key, cat] of Object.entries(lhr.categories)) {
          // Unscored, but nothing errored: every contributing audit was
          // not-applicable to this page. That is not a failure and it is not a
          // zero — it is "no verdict". Record it, score it never, hide it never.
          if (cat.score === null || cat.score === undefined) {
            notApplicable.push(key);
            findings.push({
              id: `lh-${key}-not-measured`,
              title: `Lighthouse returned no ${cat.title} score — no applicable audits for this page`,
              severity: "info",
              needsReview: true,
              location: url,
              remediation: `Confirm ${cat.title} is genuinely not applicable here; if it should have scored, the audit inputs are missing.`,
            });
            continue;
          }
          const score = cat.score;
          scores[key] = score;
          const threshold = THRESHOLDS[key];
          if (threshold !== undefined && score < threshold) {
            findings.push({
              id: `lh-${key}`,
              title: `Lighthouse ${cat.title} score ${(score * 100).toFixed(0)} < ${(threshold * 100).toFixed(0)}`,
              severity: SEVERITY_BY_SCORE(score),
              standard: "Lighthouse / Core Web Vitals",
              location: url,
              remediation: `Open the full Lighthouse report for ${cat.title} opportunities.`,
            });
          }
        }
      }

      // Nothing errored, but nothing scored either — every category came back
      // not-applicable. That is not a clean page, it is an unmeasured one.
      if (Object.keys(scores).length === 0) {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          findings: [],
          note: "Lighthouse scored no categories at all — the page was never measured, so the scores are unknown, not passing.",
          durationMs: Date.now() - start,
        };
      }

      if (findings.length === 0) {
        findings.push({
          id: "lh-ok",
          title: `Lighthouse category scores meet thresholds (${Object.keys(scores).join(", ")})`,
          severity: "info",
        });
      }

      return {
        runnerId: this.id,
        domain: this.domain,
        status: "ok",
        note: notApplicable.length
          ? `not scored (no applicable audits): ${notApplicable.join(", ")}`
          : undefined,
        findings,
        durationMs: Date.now() - start,
        meta: { scores, notApplicable },
      };
    } catch (err) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `lighthouse failed: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
      };
    } finally {
      try {
        await chrome.kill();
      } catch {
        /* already gone */
      }
    }
  },
};
