import AxeBuilder from "@axe-core/playwright";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { BrowserSession } from "../util/browser.js";
import { probeTarget } from "../util/authgate.js";

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

// Reveal-on-scroll is a false-NEGATIVE machine, and those are worse than false
// positives: a page that hides its content until it scrolls into view is scanned
// while that content is still `opacity: 0`, axe treats it as not rendered, and
// the run comes back "clean". It looks like a pass. It is an audit of nothing.
//
// Measured on 42labs.io's homepage (cards gated by an IntersectionObserver):
//   without scrolling → 0 violations
//   with scrolling    → 1 violation, 3 contrast nodes
//
// Note this is specifically about *reveal gating*, not about axe ignoring
// off-screen elements — axe finds off-viewport nodes fine (verified: tron.42labs.io
// and 42piratas.com/datasheet/ report identical findings scrolled or not). What it
// cannot see is content the page itself is still hiding.
//
// So: walk the whole page to trigger every observer, return to the top, and let
// the reveal animations settle before analysing.
async function revealLazyContent(page: import("playwright").Page): Promise<void> {
  await page
    .evaluate(async () => {
      const step = Math.max(200, window.innerHeight * 0.8);
      const height = () =>
        Math.max(
          document.body.scrollHeight,
          document.documentElement.scrollHeight,
        );
      // Guard against pages that grow as you scroll (infinite feeds).
      for (let y = 0, guard = 0; y < height() && guard < 60; y += step, guard++) {
        window.scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 100));
      }
      window.scrollTo(0, 0);
      await new Promise((r) => setTimeout(r, 150));
    })
    .catch(() => {});
}

// axe's color-contrast check reads the CSS `color` computed style as "the
// foreground". When an element has a -webkit-text-stroke, some renderers'
// paint order means axe samples the *stroke* color instead of the actual
// text fill — a node whose real fill/background ratio is 8.59:1 (compliant)
// gets reported failing at 2.19:1 (the stroke color's ratio). Reproduced on
// two separate repos.
//
// We can't fix axe's sampling, but we can tell when it's unreliable: any
// node with a non-none/non-zero -webkit-text-stroke gets its contrast
// finding downgraded to "needs manual review" rather than a hard failure —
// never silently dropped, always with the reason stated.
async function hasTextStroke(
  page: import("playwright").Page,
  target: unknown,
): Promise<boolean> {
  if (!Array.isArray(target) || target.length === 0) return false;
  const selector = target[target.length - 1];
  if (typeof selector !== "string") return false;
  return page
    .$eval(selector, (el) => {
      const width = getComputedStyle(el).getPropertyValue("-webkit-text-stroke-width").trim();
      return width !== "" && width !== "0px" && width !== "0";
    })
    .catch(() => false);
}

export const a11yRunner: Runner = {
  id: "a11y",
  domain: "a11y",
  title: "Accessibility (WCAG 2.2 AA, incl. color contrast)",
  requires: { target: true, browser: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Refuse before launching a browser session on content that isn't the
    // site: an auth-gate redirect (Cloudflare Access, Vercel SSO, Okta,
    // Auth0, ...) or a non-2xx/3xx response. Grading either lies about the
    // site under audit.
    const probe = await probeTarget(ctx.run.baseUrl);
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
          // Scrolling before hydration is a no-op: the IntersectionObservers that
          // gate reveal-on-scroll content aren't attached yet, so nothing reveals
          // and the scan still sees an empty page. Let the client mount first.
          await page
            .waitForLoadState("networkidle", { timeout: 5_000 })
            .catch(() => {});
          await revealLazyContent(page);
          await settleTransitions(page);
          const results = await new AxeBuilder({ page })
            .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
            .analyze();

          for (const v of results.violations) {
            let nodes = v.nodes;
            let strokeNodes: typeof v.nodes = [];

            if (v.id === "color-contrast") {
              const partitioned = await Promise.all(
                v.nodes.map(async (node) => ({
                  node,
                  stroke: await hasTextStroke(page, node.target),
                })),
              );
              nodes = partitioned.filter((p) => !p.stroke).map((p) => p.node);
              strokeNodes = partitioned.filter((p) => p.stroke).map((p) => p.node);
              contrastNodes += v.nodes.length;
            }

            if (strokeNodes.length > 0) {
              const target = strokeNodes[0]?.target?.join(" ") ?? "";
              const key = `a11y-color-contrast-text-stroke::${target}`;
              if (seen.has(key)) {
                seen.get(key)!.count++;
              } else {
                seen.set(key, {
                  count: 1,
                  finding: {
                    id: "a11y-color-contrast-text-stroke",
                    title: `${strokeNodes.length} node${strokeNodes.length === 1 ? "" : "s"} use -webkit-text-stroke — the contrast checker reads the stroke colour as the foreground instead of the actual text fill`,
                    severity: "info",
                    needsReview: true,
                    standard: "WCAG 1.4.3 (needs manual verification)",
                    location: `${url} ${target}`.trim(),
                    remediation:
                      "Verify contrast manually against the real text-fill `color` vs `background-color` (not the stroke). If the fill/background ratio meets 4.5:1, this is a false positive.",
                    evidence: strokeNodes[0]?.html?.slice(0, 240),
                  },
                });
              }
            }

            if (nodes.length === 0) continue; // every node here was stroke-affected

            const sev = IMPACT_TO_SEVERITY[v.impact ?? "minor"] ?? "low";
            const target = nodes[0]?.target?.join(" ") ?? "";
            const key = `${v.id}::${target}`;
            if (seen.has(key)) {
              seen.get(key)!.count++;
              continue;
            }
            seen.set(key, {
              count: 1,
              finding: {
                id: `a11y-${v.id}`,
                title: `${v.help} (${nodes.length} node${nodes.length === 1 ? "" : "s"})`,
                severity: sev,
                standard: (v.tags.find((t) => t.startsWith("wcag")) ?? "WCAG").toUpperCase(),
                location: `${url} ${target}`.trim(),
                remediation: v.helpUrl,
                evidence: nodes[0]?.html?.slice(0, 240),
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
