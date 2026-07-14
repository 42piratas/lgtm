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

      // Whether a category score can be trusted is decided by the AUDITS inside
      // it, never by the category number alone. From lighthouse/core/scoring.js:
      //
      //   • scoreAllCategories() forces weight = 0 for every audit whose
      //     scoreDisplayMode is notApplicable / informative / manual.
      //   • arithmeticMean() drops all weight-0 items BEFORE its null check,
      //     then returns `sum / weight || 0`.
      //
      // Two consequences the obvious reading gets backwards:
      //   1. A category only goes `score: null` because a WEIGHTED audit was
      //      unscored — i.e. one that errored. Null means "not measured".
      //   2. A category whose every weighted audit is not-applicable does NOT
      //      come back null. It comes back **0** — `0/0 || 0`. Scoring that 0
      //      against the threshold would report a failing performance grade for
      //      a page that was never measured: the same lie as `?? 0`, wearing a
      //      different hat.
      //
      // So we split by cause, the way Lighthouse CI (Google's own build gate)
      // does: an audit that ran and produced nothing is a hard failure ("Audit
      // did not produce a value at all"); a not-applicable audit is not a defect.
      const audits =
        (lhr as { audits?: Record<string, { scoreDisplayMode?: string; title?: string }> })
          .audits ?? {};
      type Ref = { id: string; weight?: number };
      const refsOf = (cat: unknown): Ref[] =>
        ((cat as { auditRefs?: Ref[] }).auditRefs ?? []).map((r) => ({
          id: r.id,
          weight: r.weight ?? 1,
        }));

      const scores: Record<string, number> = {};
      const notMeasured: string[] = [];

      for (const [key, cat] of Object.entries(lhr.categories)) {
        const refs = refsOf(cat);

        // An errored audit that actually carries weight is what nulls a category.
        // A zero-weight one doesn't affect the score, so it must not fail the run.
        const errored = refs.filter(
          (r) => (r.weight ?? 1) > 0 && audits[r.id]?.scoreDisplayMode === "error",
        );
        if (errored.length > 0) {
          return {
            runnerId: this.id,
            domain: this.domain,
            status: "error",
            findings: [],
            note: `Lighthouse audits errored, so ${key} could not be measured — the scores are unknown, not passing: ${errored
              .map((r) => audits[r.id]?.title ?? r.id)
              .slice(0, 3)
              .join("; ")}`,
            durationMs: Date.now() - start,
          };
        }

        // Every contributing audit was not-applicable → Lighthouse hands back 0,
        // and that 0 is not a score. Never grade it; surface it for a human.
        const weighted = refs.filter((r) => (r.weight ?? 1) > 0);
        if (refs.length > 0 && weighted.length === 0) {
          notMeasured.push(key);
          findings.push({
            id: `lh-${key}-not-measured`,
            title: `Lighthouse produced no ${cat.title} score — every audit in it was not applicable to this page`,
            severity: "info",
            needsReview: true,
            location: url,
            remediation: `Confirm ${cat.title} is genuinely not applicable here; if it should have scored, the audit inputs are missing.`,
          });
          continue;
        }

        // Null with nothing errored to explain it: unknown, and unknown is not clean.
        if (cat.score === null || cat.score === undefined) {
          return {
            runnerId: this.id,
            domain: this.domain,
            status: "error",
            findings: [],
            note: `Lighthouse returned no ${key} score — the category was not measured, so the score is unknown, not passing.`,
            durationMs: Date.now() - start,
          };
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

      // Nothing errored, but nothing scored either — the page was never measured.
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
        note: notMeasured.length
          ? `not scored (no applicable audits): ${notMeasured.join(", ")}`
          : undefined,
        findings,
        durationMs: Date.now() - start,
        meta: { scores, notMeasured },
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
