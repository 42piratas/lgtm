import AxeBuilder from "@axe-core/playwright";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { BrowserSession } from "../util/browser.js";

// Accessibility via axe-core (WCAG 2.0/2.1/2.2 A + AA), driven through a real
// authenticated browser so app surfaces behind login are covered. Color
// contrast is one axe rule among the WCAG-tagged set; it is reported inline.

const IMPACT_TO_SEVERITY: Record<string, Finding["severity"]> = {
  critical: "high",
  serious: "high",
  moderate: "medium",
  minor: "low",
};

// axe samples computed styles at the instant it runs. If a CSS transition on
// color/background-color is still animating, it reads a *blended* mid-transition
// value and reports a contrast violation against a color the user never sees —
// a node whose settled ratio is 5.97:1 gets flagged as failing. Firing right
// after `load` is squarely inside that window, so every scanned page with a
// color transition produced false contrast findings.
//
// Wait for the animations the page itself declares: resolve when every running
// Animation settles, capped so a decorative infinite loop can't hang the run.
const SETTLE_CAP_MS = 2_000;

async function settleTransitions(page: import("playwright").Page): Promise<void> {
  await page
    .evaluate(async (cap: number) => {
      const running = document
        .getAnimations()
        .filter((a) => a.playState === "running")
        .map((a) => a.finished.catch(() => undefined));
      if (running.length === 0) return;
      // Infinite animations never settle — never let them hold the scan open.
      await Promise.race([
        Promise.allSettled(running),
        new Promise((r) => setTimeout(r, cap)),
      ]);
    }, SETTLE_CAP_MS)
    .catch(() => {});
}

export const a11yRunner: Runner = {
  id: "a11y",
  domain: "a11y",
  title: "Accessibility (WCAG 2.2 AA, incl. color contrast)",
  requires: { target: true, browser: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const session = new BrowserSession(ctx.site);
    let authNote = "";
    if (session.authRequestedButMissing()) {
      authNote =
        " (auth storageState missing — public view only; run `lgtm auth` first)";
    }

    try {
      const context = await session.context();
      // De-dup findings across pages by (rule, target); count occurrences.
      const seen = new Map<string, { finding: Finding; count: number }>();
      let contrastNodes = 0;

      for (const url of ctx.urls) {
        const page = await context.newPage();
        try {
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
          // Let late-mounted client UI settle without hanging on long-poll/analytics.
          await page.waitForLoadState("load", { timeout: 10_000 }).catch(() => {});
          await settleTransitions(page);
          const results = await new AxeBuilder({ page })
            .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
            .analyze();

          for (const v of results.violations) {
            if (v.id === "color-contrast") contrastNodes += v.nodes.length;
            const sev = IMPACT_TO_SEVERITY[v.impact ?? "minor"] ?? "low";
            const target = v.nodes[0]?.target?.join(" ") ?? "";
            const key = `${v.id}::${target}`;
            if (seen.has(key)) {
              seen.get(key)!.count++;
              continue;
            }
            seen.set(key, {
              count: 1,
              finding: {
                id: `a11y-${v.id}`,
                title: `${v.help} (${v.nodes.length} node${v.nodes.length === 1 ? "" : "s"})`,
                severity: sev,
                standard: (v.tags.find((t) => t.startsWith("wcag")) ?? "WCAG").toUpperCase(),
                location: `${url} ${target}`.trim(),
                remediation: v.helpUrl,
                evidence: v.nodes[0]?.html?.slice(0, 240),
              },
            });
          }
        } catch (err) {
          findings.push({
            id: `a11y-nav-${url}`,
            title: `Could not analyze ${url}: ${(err as Error).message}`,
            severity: "info",
          });
        } finally {
          await page.close().catch(() => {});
        }
      }

      for (const { finding } of seen.values()) findings.push(finding);

      const violationCount = [...seen.values()].length;
      if (violationCount === 0) {
        findings.push({
          id: "a11y-ok",
          title: `No WCAG 2.2 AA violations across ${ctx.urls.length} page(s)${authNote}`,
          severity: "info",
        });
      }

      return {
        runnerId: this.id,
        domain: this.domain,
        status: "ok",
        note: authNote.trim() || undefined,
        findings,
        durationMs: Date.now() - start,
        meta: { pages: ctx.urls.length, contrastNodes },
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
      await session.close();
    }
  },
};
