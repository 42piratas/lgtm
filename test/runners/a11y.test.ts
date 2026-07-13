import { describe, it, expect, vi, beforeEach } from "vitest";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// a11y.ts's IMPACT_TO_SEVERITY table and its axe-violation handling
// (de-dup by rule+target, contrastNodes tally, the "clean" info fallback)
// are pure logic wrapped around a real browser. We exercise the actual
// runner by mocking its two I/O boundaries — BrowserSession and
// @axe-core/playwright's AxeBuilder — rather than launching Chromium, so
// the suite stays hermetic and fast. src/runners/a11y.ts itself is not
// touched.
//
// What we deliberately do NOT claim to test: the CSS-transition-timing bug
// (contrast read mid-animation) and the reveal-on-scroll false-negative bug
// are about real browser paint/animation timing that a mocked page can't
// reproduce — those need a live Playwright run against a real page. We do
// assert the *sequencing* the reveal-on-scroll fix depends on (scroll/settle
// before analyze), which is the regression guard available without a
// browser.

// Single shared timeline so the reveal-on-scroll regression guard below can
// assert relative order, not just call counts.
const callOrder: string[] = [];

// The computed style each fake page hands back to a11y.ts's $eval probe.
// Default: no stroke at all, so contrast findings behave exactly as they did
// before the -webkit-text-stroke work (42L-973 #5) — the stroke path is opt-in
// per-test via `nextStrokeStyle`.
const NO_STROKE_STYLE = {
  strokeWidth: "0px",
  color: "rgb(0, 0, 0)",
  fontSize: "16px",
  fontWeight: "400",
  bgColors: ["rgb(255, 255, 255)"],
  bgImages: ["none"],
  opacities: ["1"],
};
let nextStrokeStyle: Record<string, unknown> = NO_STROKE_STYLE;

function makeFakePage(): Record<string, unknown> {
  return {
    goto: vi.fn().mockResolvedValue({}),
    waitForLoadState: vi.fn().mockResolvedValue(undefined),
    evaluate: vi.fn().mockImplementation(async () => {
      callOrder.push("evaluate");
      return undefined;
    }),
    // a11y.ts reads each flagged node's computed style through page.$eval to
    // decide whether axe misread a -webkit-text-stroke as the foreground.
    // A real Playwright Page has $eval; this mock must too, or the runner
    // throws and every a11y test silently degrades into asserting nothing.
    $eval: vi.fn().mockImplementation(async () => nextStrokeStyle),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

let nextViolations: unknown[][] = [];
let authRequestedButMissing = false;

// A plain class, not vi.fn().mockImplementation(() => ({...})) — `new`
// semantics for a mocked constructor are unreliable across vi.fn wrapping,
// a real class guarantees the instance shape a11y.ts expects.
class FakeBrowserSession {
  async context() {
    return { newPage: async () => makeFakePage() };
  }
  authRequestedButMissing() {
    return authRequestedButMissing;
  }
  async close() {}
}

vi.mock("../../src/util/browser.js", () => ({
  BrowserSession: FakeBrowserSession,
}));

// a11y.ts probes the target before launching a browser, to refuse auth-gated
// or non-2xx responses (42L-973 #1/#2). Left unmocked that is a REAL network
// call to example.com from the unit suite — slow, flaky, and offline-hostile.
// The probe's own logic is tested directly in test/util/authgate.test.ts.
let probeResult: { ok: boolean; note?: string } = { ok: true, status: 200 } as {
  ok: boolean;
  note?: string;
};
vi.mock("../../src/util/authgate.js", () => ({
  probeTarget: async () => probeResult,
}));

// Same reasoning as FakeBrowserSession above: a real class so `new
// AxeBuilder(...)` gets the instance we actually intend.
class FakeAxeBuilder {
  withTags() {
    return this;
  }
  async analyze() {
    callOrder.push("analyze");
    const violations = nextViolations.shift() ?? [];
    return { violations };
  }
}

vi.mock("@axe-core/playwright", () => ({
  default: FakeAxeBuilder,
}));

const { a11yRunner } = await import("../../src/runners/a11y.js");

function violation(
  id: string,
  impact: string | undefined,
  target: string,
  nodeCount = 1,
): Record<string, unknown> {
  return {
    id,
    impact,
    help: `${id} help text`,
    tags: ["wcag2a", "wcag21aa"],
    helpUrl: `https://dequeuniversity.com/rules/axe/${id}`,
    nodes: Array.from({ length: nodeCount }, () => ({
      target: [target],
      html: `<div class="${target}"></div>`,
    })),
  };
}

function ctx(urls: string[]): RunnerContext {
  const site: SiteConfig = {
    name: "site",
    baseUrl: urls[0]!,
    routes: [],
    auth: { type: "none" },
    failOn: "high",
  };
  return {
    site,
    run: { baseUrl: urls[0]!, isLocalhost: false, allowActive: false, outDir: "", stamp: "" },
    urls,
    caps: { docker: false, browser: true },
    log: () => {},
  };
}

beforeEach(() => {
  nextViolations = [];
  authRequestedButMissing = false;
  callOrder.length = 0;
  nextStrokeStyle = NO_STROKE_STYLE;
  probeResult = { ok: true };
});

describe("a11yRunner — IMPACT_TO_SEVERITY mapping", () => {
  it("maps axe impact levels onto lgtm severities exactly as configured", async () => {
    nextViolations = [
      [
        violation("color-contrast", "critical", "#a"),
        violation("label-missing", "serious", "#b"),
        violation("landmark-unique", "moderate", "#c"),
        violation("region", "minor", "#d"),
      ],
    ];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    const byId = (id: string) => result.findings.find((f) => f.id === `a11y-${id}`)!;
    expect(byId("color-contrast").severity).toBe("high");
    expect(byId("label-missing").severity).toBe("high");
    expect(byId("landmark-unique").severity).toBe("medium");
    expect(byId("region").severity).toBe("low");
  });

  it("defaults an undefined impact to the 'minor' mapping (low)", async () => {
    nextViolations = [[violation("mystery-rule", undefined, "#e")]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    expect(result.findings.find((f) => f.id === "a11y-mystery-rule")!.severity).toBe("low");
  });

  it("falls back to low for an impact value axe hasn't defined here", async () => {
    nextViolations = [[violation("weird-rule", "unheard-of", "#f")]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    expect(result.findings.find((f) => f.id === "a11y-weird-rule")!.severity).toBe("low");
  });
});

describe("a11yRunner — de-dup and tallying across pages", () => {
  it("de-dupes the same rule+target seen on two different pages into one finding", async () => {
    nextViolations = [
      [violation("color-contrast", "serious", "#shared", 3)],
      [violation("color-contrast", "serious", "#shared", 3)],
    ];
    const result = await a11yRunner.run(ctx(["https://example.com/a", "https://example.com/b"]));
    const contrastFindings = result.findings.filter((f) => f.id === "a11y-color-contrast");
    expect(contrastFindings).toHaveLength(1);
  });

  it("keeps the SAME rule on DISTINCT targets as separate findings — the de-dup key is rule+target, not rule alone", async () => {
    // Guards the de-dup key itself. If the key collapses from
    // `${v.id}::${target}` to just `${v.id}`, two genuinely different failing
    // elements silently merge into one finding and an operator fixes one and
    // thinks they're done. Same rule, two different targets, one page.
    nextViolations = [
      [
        violation("color-contrast", "serious", "#header-cta"),
        violation("color-contrast", "serious", "#footer-link"),
      ],
    ];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    const contrastFindings = result.findings.filter((f) => f.id === "a11y-color-contrast");
    expect(contrastFindings).toHaveLength(2);
    expect(contrastFindings.map((f) => f.location).sort()).toEqual([
      "https://example.com #footer-link",
      "https://example.com #header-cta",
    ]);
  });

  it("keeps DISTINCT rules on the same target as separate findings", async () => {
    nextViolations = [
      [
        violation("color-contrast", "serious", "#cta"),
        violation("link-name", "serious", "#cta"),
      ],
    ];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    expect(result.findings.filter((f) => f.id.startsWith("a11y-"))).toHaveLength(2);
  });

  it("tallies contrastNodes across every color-contrast violation, including de-duped repeats", async () => {
    nextViolations = [
      [violation("color-contrast", "serious", "#shared", 3)],
      [violation("color-contrast", "serious", "#shared", 3)],
    ];
    const result = await a11yRunner.run(ctx(["https://example.com/a", "https://example.com/b"]));
    expect(result.meta?.contrastNodes).toBe(6);
  });

  it("reports one info finding, mentioning page count, when nothing is found", async () => {
    nextViolations = [[], []];
    const result = await a11yRunner.run(ctx(["https://example.com/a", "https://example.com/b"]));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.id).toBe("a11y-ok");
    expect(result.findings[0]!.title).toMatch(/2 page/);
  });

  it("notes when auth was configured but the storageState session is missing", async () => {
    authRequestedButMissing = true;
    nextViolations = [[]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    expect(result.note).toMatch(/auth storageState missing/);
  });
});

describe("a11yRunner — regression guard for the reveal-on-scroll false negative (bug #2)", () => {
  it("triggers the page's own reveal/settle logic (page.evaluate) before running axe's analyze", async () => {
    nextViolations = [[]];
    await a11yRunner.run(ctx(["https://example.com"]));
    // revealLazyContent + settleTransitions each call page.evaluate once,
    // and both must happen before AxeBuilder#analyze — a scan that analyzes
    // first (as the historical bug did) audits a page that hasn't revealed
    // its scroll-gated content yet, and comes back clean having seen nothing.
    expect(callOrder.filter((c) => c === "evaluate").length).toBeGreaterThanOrEqual(2);
    expect(callOrder.filter((c) => c === "analyze")).toHaveLength(1);
    expect(callOrder.indexOf("analyze")).toBe(callOrder.length - 1);
    expect(callOrder.slice(0, -1).every((c) => c === "evaluate")).toBe(true);
  });
});

// ── 42L-973 #5: -webkit-text-stroke contrast ────────────────────────────────
//
// axe reads the stroke colour as the foreground instead of the text fill, so a
// compliant node gets reported failing. The fix downgrades those to a visible
// "needs review" note — but ONLY when the real fill/background ratio actually
// passes. Downgrading every stroked node would trade a false positive for a
// false negative, which is the worse bug; these tests pin both directions.

describe("a11yRunner — -webkit-text-stroke contrast (bug #5)", () => {
  const strokedButCompliant = {
    strokeWidth: "3px",
    color: "rgb(74, 74, 74)", // #4A4A4A on white ≈ 8.59:1 — genuinely passes
    fontSize: "28px",
    fontWeight: "600",
    bgColors: ["rgba(0, 0, 0, 0)", "rgb(255, 255, 255)"],
    bgImages: ["none", "none"],
    opacities: ["1", "1"],
  };
  const strokedAndGenuinelyBad = {
    strokeWidth: "2px",
    color: "rgb(221, 221, 221)", // #DDDDDD on white ≈ 1.3:1 — genuinely fails
    fontSize: "16px",
    fontWeight: "400",
    bgColors: ["rgba(0, 0, 0, 0)", "rgb(255, 255, 255)"],
    bgImages: ["none", "none"],
    opacities: ["1", "1"],
  };

  it("downgrades a stroked node whose REAL fill contrast passes to a visible needs-review note, not a hard failure", async () => {
    nextStrokeStyle = strokedButCompliant;
    nextViolations = [[violation("color-contrast", "serious", "h1")]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));

    // No hard contrast failure...
    expect(result.findings.find((f) => f.id === "a11y-color-contrast")).toBeUndefined();
    // ...but absolutely not dropped either.
    const review = result.findings.find((f) => f.id === "a11y-color-contrast-text-stroke")!;
    expect(review).toBeDefined();
    expect(review.needsReview).toBe(true);
    expect(review.severity).toBe("info"); // never counts toward failOn
    expect(review.title).toMatch(/-webkit-text-stroke/);
  });

  it("KEEPS a hard failure when the stroked node's real fill contrast is genuinely bad — no false negative", async () => {
    nextStrokeStyle = strokedAndGenuinelyBad;
    nextViolations = [[violation("color-contrast", "serious", "p")]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));

    const hard = result.findings.find((f) => f.id === "a11y-color-contrast")!;
    expect(hard).toBeDefined();
    expect(hard.severity).toBe("high");
    expect(hard.needsReview).toBeFalsy();
    expect(result.findings.find((f) => f.id === "a11y-color-contrast-text-stroke")).toBeUndefined();
  });

  it("leaves an unstroked contrast violation completely alone", async () => {
    nextStrokeStyle = NO_STROKE_STYLE;
    nextViolations = [[violation("color-contrast", "serious", "#x")]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    expect(result.findings.find((f) => f.id === "a11y-color-contrast")!.severity).toBe("high");
    expect(result.findings.find((f) => f.id === "a11y-color-contrast-text-stroke")).toBeUndefined();
  });

  it("does not touch non-contrast rules even on a stroked element", async () => {
    nextStrokeStyle = strokedButCompliant;
    nextViolations = [[violation("link-name", "serious", "a")]];
    const result = await a11yRunner.run(ctx(["https://example.com"]));
    expect(result.findings.find((f) => f.id === "a11y-link-name")!.severity).toBe("high");
  });
});

// ── 42L-973 #1/#2: refuse to score a gated / unfetchable target ─────────────
describe("a11yRunner — refuses to score when the probe says the target isn't the site", () => {
  it("errors instead of scanning when the target is behind an auth gate", async () => {
    probeResult = {
      ok: false,
      note: "refusing to score — redirected to a known auth gate (labs42.cloudflareaccess.com)",
    };
    nextViolations = [[violation("color-contrast", "serious", "#x")]];
    const result = await a11yRunner.run(ctx(["https://ds.example.com"]));
    expect(result.status).toBe("error");
    expect(result.note).toMatch(/auth gate/);
    // It must NOT have produced a grade-able finding list off someone else's page.
    expect(result.findings).toHaveLength(0);
  });
});
