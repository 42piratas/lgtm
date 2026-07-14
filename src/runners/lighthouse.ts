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

      const scores: Record<string, number> = {};
      {
        for (const [key, cat] of Object.entries(lhr.categories)) {
          const score = cat.score ?? 0;
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

      if (findings.length === 0) {
        findings.push({
          id: "lh-ok",
          title: "Lighthouse category scores meet thresholds",
          severity: "info",
        });
      }

      return {
        runnerId: this.id,
        domain: this.domain,
        status: "ok",
        findings,
        durationMs: Date.now() - start,
        meta: { scores },
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
