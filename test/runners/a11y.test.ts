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

function makeFakePage(): Record<string, unknown> {
  return {
    goto: vi.fn().mockResolvedValue({}),
    waitForLoadState: vi.fn().mockResolvedValue(undefined),
    evaluate: vi.fn().mockImplementation(async () => {
      callOrder.push("evaluate");
      return undefined;
    }),
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
