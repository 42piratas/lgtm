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
// The naive fix — "any stroked node becomes needs-review" — trades a false
// positive for a FALSE NEGATIVE, which is strictly worse: a stroked element
// whose fill genuinely fails contrast would quietly stop failing the build.
// So we don't just detect the stroke, we recompute the ratio axe *should*
// have measured (real text fill vs. the nearest opaque background) and only
// downgrade when that ratio actually passes WCAG. A stroked node whose real
// fill contrast is bad stays a hard failure.
//
// The recomputation is deliberately conservative: if anything is ambiguous
// (translucent backgrounds, gradients, images, unparseable colors) we return
// "unknown" and leave axe's original hard failure standing. We only ever
// *downgrade* on positive evidence that the text is genuinely compliant.
export type StrokeVerdict =
  | "no-stroke"
  | "stroke-fill-passes"
  | "stroke-fill-fails-or-unknown";

/** Raw computed-style data read out of the page — no logic, just strings. */
export interface StrokeStyle {
  strokeWidth: string;
  color: string;
  fontSize: string;
  fontWeight: string;
  /** backgroundColor of the node and each ancestor, nearest first. */
  bgColors: string[];
  /** backgroundImage of the node and each ancestor, nearest first. */
  bgImages: string[];
  /**
   * Computed `opacity` of the node and each ancestor, nearest first.
   *
   * Element opacity is NOT the same thing as a colour's alpha channel, and it
   * is the sneaky one: `color` can be a fully opaque black while an ancestor
   * `opacity: 0.28` renders that text as light grey. Reading only the colour
   * alpha (as the first cut of this did) computes 21:1 for text that the user
   * actually sees at ~2.3:1 — and would then downgrade a genuine contrast
   * failure to a non-blocking note. Exactly the false negative this whole
   * classifier exists to avoid.
   */
  opacities: string[];
}

/** "rgb(1, 2, 3)" / "rgba(1, 2, 3, .5)" → [r,g,b,a], or null if unparseable. */
function parseRgb(c: string): [number, number, number, number] | null {
  const m = c.match(/rgba?\(([^)]+)\)/i);
  if (!m || !m[1]) return null;
  const p = m[1].split(",").map((x) => Number(x.trim()));
  const [r, g, b] = p;
  if (r === undefined || g === undefined || b === undefined) return null;
  if ([r, g, b].some((n) => Number.isNaN(n))) return null;
  const a = p[3] === undefined ? 1 : p[3];
  return [r, g, b, Number.isNaN(a) ? 1 : a];
}

function relativeLuminance(rgb: [number, number, number, number]): number {
  const ch = [rgb[0], rgb[1], rgb[2]].map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}

export function contrastRatio(
  fg: [number, number, number, number],
  bg: [number, number, number, number],
): number {
  const l1 = relativeLuminance(fg);
  const l2 = relativeLuminance(bg);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

/**
 * The whole decision, as a pure function of the raw style data — so it is
 * directly unit-testable without a browser, and so none of it has to survive
 * being serialized into a page (see the note on readStrokeStyle below).
 */
export function classifyStrokeStyle(st: StrokeStyle): StrokeVerdict {
  const w = st.strokeWidth.trim();
  if (w === "" || w === "0px" || w === "0") return "no-stroke";

  const fg = parseRgb(st.color);
  if (!fg || fg[3] < 1) return "stroke-fill-fails-or-unknown"; // translucent text → unsure

  // Any element opacity below 1, on the node or ANY ancestor, fades the text
  // toward its backdrop by an amount we are not going to try to model. We
  // cannot then claim the node is compliant, so we don't: keep axe's hard
  // failure. (Opaque colour + `opacity: 0.28` ancestor renders black text as
  // light grey — 21:1 on paper, ~2.3:1 in the user's eyes.)
  for (const o of st.opacities) {
    const v = parseFloat(o);
    if (!Number.isNaN(v) && v < 1) return "stroke-fill-fails-or-unknown";
  }

  // Nearest ancestor with a fully opaque background colour. Anything else
  // (image, gradient, translucent stack) is ambiguous → leave axe's call alone.
  let bg: [number, number, number, number] | null = null;
  for (let i = 0; i < st.bgColors.length; i++) {
    const img = st.bgImages[i];
    if (img && img !== "none") return "stroke-fill-fails-or-unknown";
    const c = parseRgb(st.bgColors[i] ?? "");
    if (c && c[3] === 1) {
      bg = c;
      break;
    }
    if (c && c[3] > 0) return "stroke-fill-fails-or-unknown"; // translucent layer
  }
  if (!bg) bg = [255, 255, 255, 1]; // canvas default

  // WCAG AA: 3:1 for large text (>=24px, or >=18.66px bold), else 4.5:1.
  const size = parseFloat(st.fontSize);
  const weight = Number(st.fontWeight) || 400;
  const large = size >= 24 || (size >= 18.66 && weight >= 700);
  const threshold = large ? 3 : 4.5;

  return contrastRatio(fg, bg) >= threshold
    ? "stroke-fill-passes"
    : "stroke-fill-fails-or-unknown";
}

/**
 * Read the raw style data out of the page. Deliberately contains NO named
 * inner functions: tsx/esbuild rewrites named function expressions with a
 * `__name` helper that does not exist inside the browser context, so a
 * callback with helper functions throws `ReferenceError: __name is not
 * defined` the moment it is serialized into the page — which `.catch()` then
 * swallows, silently degrading every node to the fallback verdict. (That bug
 * was live in the first cut of this fix.) Keep this callback dumb: read
 * strings, return strings. All logic lives in classifyStrokeStyle above.
 */
async function readStrokeStyle(
  page: import("playwright").Page,
  selector: string,
): Promise<StrokeStyle | null> {
  return page
    .$eval(selector, (el) => {
      const cs = getComputedStyle(el);
      const bgColors: string[] = [];
      const bgImages: string[] = [];
      const opacities: string[] = [];
      let node: Element | null = el;
      while (node) {
        const s = getComputedStyle(node);
        bgColors.push(s.backgroundColor);
        bgImages.push(s.backgroundImage);
        opacities.push(s.opacity);
        node = node.parentElement;
      }
      return {
        strokeWidth: cs.getPropertyValue("-webkit-text-stroke-width"),
        color: cs.color,
        fontSize: cs.fontSize,
        fontWeight: cs.fontWeight,
        bgColors,
        bgImages,
        opacities,
      };
    })
    .catch(() => null);
}

async function classifyStroke(
  page: import("playwright").Page,
  target: unknown,
): Promise<StrokeVerdict> {
  if (!Array.isArray(target) || target.length === 0) return "no-stroke";
  const selector = target[target.length - 1];
  if (typeof selector !== "string") return "no-stroke";
  const style = await readStrokeStyle(page, selector);
  if (!style) return "no-stroke"; // couldn't read it → leave axe's verdict alone
  return classifyStrokeStyle(style);
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

    // Zero pages audited is zero evidence. The old code walked an empty loop,
    // counted zero violations, and reported "No WCAG 2.2 AA violations across
    // 0 page(s)" — grade A for auditing nothing at all.
    if (ctx.urls.length === 0) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: "no URLs to audit — zero pages were scanned, so the result is unknown, not clean",
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
      const failedNavigations: string[] = [];
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
                  verdict: await classifyStroke(page, node.target),
                })),
              );
              // ONLY "stroke-fill-passes" is downgraded to needs-review — a
              // stroked node whose real fill contrast is bad (or ambiguous)
              // stays in `nodes` and remains a hard failure. Trading a false
              // positive for a false negative would be the worse bug.
              strokeNodes = partitioned
                .filter((p) => p.verdict === "stroke-fill-passes")
                .map((p) => p.node);
              nodes = partitioned
                .filter((p) => p.verdict !== "stroke-fill-passes")
                .map((p) => p.node);
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
                    title: `${strokeNodes.length} node${strokeNodes.length === 1 ? "" : "s"} use -webkit-text-stroke and the real text fill DOES meet WCAG AA against its background — axe read the stroke colour as the foreground instead of the fill`,
                    severity: "info",
                    needsReview: true,
                    standard: "WCAG 1.4.3 (needs manual verification)",
                    location: `${url} ${target}`.trim(),
                    remediation:
                      "Likely a false positive: the recomputed text-fill vs background ratio meets the AA threshold. Confirm visually — only nodes whose real fill contrast passes are downgraded here; a stroked node with genuinely poor fill contrast is still reported as a hard failure.",
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
          // A page we could not load is a page we did not audit. Recording that
          // as a severity:"info" note let realFindings() drop it, left the
          // violation count at zero, fired the "no violations" pass-note, and
          // graded the run A — a clean bill of health for a page that never
          // rendered. Same swallowed-navigation lie as the authz runner's, in
          // the runner whose whole job is looking at pages.
          failedNavigations.push(`${url}: ${(err as Error).message}`);
        } finally {
          await page.close().catch(() => {});
        }
      }

      // Findings from the pages that DID load are real and must survive the
      // error return below — a run that failed on page 3 still saw pages 1-2,
      // and throwing their violations away would be its own kind of lie.
      for (const { finding } of seen.values()) findings.push(finding);

      if (failedNavigations.length > 0) {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          note: `could not load ${failedNavigations.length} of ${ctx.urls.length} page(s) — the pages were never audited, so the result is unknown, not clean: ${failedNavigations.join("; ")}`,
          findings,
          durationMs: Date.now() - start,
        };
      }

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
