import { launch } from "chrome-launcher";
import lighthouse from "lighthouse";
import { readFileSync, existsSync } from "node:fs";
import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
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

  /**
   * Lighthouse hands back a category score of 0 for a page it could not
   * measure just as readily as for a page that measured badly (see the note
   * on weighting below). A run that scored no category at all measured
   * nothing, and has no verdict to give.
   */
  sufficient(cov: Coverage): string | null {
    // A category we could not measure is a category we cannot vouch for. Named,
    // so the operator knows which. The findings from the categories we DID
    // measure stay in the report — this refuses the verdict, not the evidence.
    const bad = Number(cov.data.categoriesUnmeasurable ?? 0);
    if (bad > 0) {
      return `${bad} categor${bad === 1 ? "y" : "ies"} could not be measured, so the scores are unknown, not passing — ${String(cov.data.unmeasurable ?? "")}`;
    }
    if (Number(cov.data.categoriesScored ?? 0) === 0) {
      return "Lighthouse scored no category — the page was never measured, so the scores are unknown, not passing";
    }
    if (Number(cov.data.auditsRun ?? 0) === 0) {
      return "no Lighthouse audit produced a value — the scores are unknown, not passing";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;

    // Refuse before spending a Chrome launch on content that isn't the site:
    // an auth-gate redirect or a non-2xx/3xx response.
    const probe = await probeTarget(url);
    if (!probe.ok) {
      return { kind: "failed", note: probe.note };
    }

    const chrome = await launch({
      chromeFlags: ["--headless=new", "--no-sandbox", "--ignore-certificate-errors"],
    }).catch(() => null);
    if (!chrome) {
      return { kind: "failed", note: "could not launch Chrome for Lighthouse" };
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
          kind: "failed",
          note: "Lighthouse returned no report — the scan produced no data, so the scores are unknown, not passing.",
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
          kind: "failed",
          note: `Lighthouse could not measure the page (${runtimeError.code}): ${runtimeError.message ?? "no detail"} — the scores are unknown, not passing.`,
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

      // Categories Lighthouse could not measure, and why. Collected rather than
      // returned on the spot: bailing out of this loop the moment a LATER
      // category fails threw away the real findings an EARLIER one had already
      // produced (a genuine performance regression, silently deleted because
      // an SEO audit errored two iterations later). Every other runner here
      // preserves what it saw before it lost certainty; this one has to as well.
      const unmeasurable: string[] = [];

      for (const [key, cat] of Object.entries(lhr.categories)) {
        const refs = refsOf(cat);

        // An errored audit that actually carries weight is what nulls a category.
        // A zero-weight one doesn't affect the score, so it must not fail the run.
        const errored = refs.filter(
          (r) => (r.weight ?? 1) > 0 && audits[r.id]?.scoreDisplayMode === "error",
        );
        if (errored.length > 0) {
          unmeasurable.push(
            `${key}: audits errored (${errored
              .map((r) => audits[r.id]?.title ?? r.id)
              .slice(0, 3)
              .join("; ")})`,
          );
          continue;
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
          unmeasurable.push(`${key}: no score returned`);
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

      // An audit that produced a value is an audit that ran. Lighthouse CI —
      // Google's own build gate — treats "audit did not produce a value at all"
      // as a hard failure for the same reason: a metric with nothing behind it
      // cannot be asserted against a threshold.
      const auditsRun = Object.values(audits).filter(
        (a) => a.scoreDisplayMode && a.scoreDisplayMode !== "error",
      ).length;

      return {
        kind: "observed",
        note: notMeasured.length
          ? `not scored (no applicable audits): ${notMeasured.join(", ")}`
          : undefined,
        findings,
        coverage: {
          trail: [
            `measured ${url}`,
            `scored ${Object.keys(scores).length} of ${Object.keys(lhr.categories).length} categories (${Object.keys(scores).join(", ") || "none"})`,
            `${auditsRun} audits produced a value`,
            ...notMeasured.map((k) => `NOT scored: ${k} (no applicable audits)`),
            ...unmeasurable.map((u) => `COULD NOT measure ${u}`),
          ],
          data: {
            categoriesRequested: Object.keys(lhr.categories).length,
            categoriesScored: Object.keys(scores).length,
            categoriesUnmeasurable: unmeasurable.length,
            unmeasurable: unmeasurable.join("; "),
            auditsRun,
          },
          provenance: "Lighthouse LHR categories + audits",
        },
        meta: { scores, notMeasured, unmeasurable },
      };
    } catch (err) {
      return {
        kind: "failed",
        note: `lighthouse failed: ${(err as Error).message}`,
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
