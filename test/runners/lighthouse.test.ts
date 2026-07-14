import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// lighthouse.ts had no tests. The logic worth guarding is pure:
//   THRESHOLDS        which category scores count as a failure
//   SEVERITY_BY_SCORE score < 0.5 → medium, else low
//   cookieHeaderFrom  turning a storageState file into a Cookie header, incl.
//                     the domain-matching that decides whether an authed page
//                     is scored logged-in or logged-out
// We mock chrome-launcher and the lighthouse package, and drive the real
// runner. No src/runners/ file is modified.

const lighthouseMock = vi.fn();
const launchMock = vi.fn();

vi.mock("chrome-launcher", () => ({
  launch: (opts: unknown) => launchMock(opts),
}));

vi.mock("lighthouse", () => ({
  default: (url: string, opts: unknown) => lighthouseMock(url, opts),
}));

// lighthouse.ts probes the target before launching Chrome, to refuse auth-gated
// / non-2xx responses (42L-973 #1/#2). Unmocked that is a REAL HTTP request to
// example.com from the unit suite — the same class of leak that took CI red on
// the ZAP tests. Injectable; default is "reachable and really the site".
let probeResult: { ok: boolean; note?: string } = { ok: true };
vi.mock("../../src/util/authgate.js", () => ({
  probeTarget: async () => probeResult,
}));

const { lighthouseRunner } = await import("../../src/runners/lighthouse.js");

let dir: string;

beforeEach(() => {
  lighthouseMock.mockReset();
  launchMock.mockReset();
  launchMock.mockResolvedValue({ port: 9222, kill: async () => {} });
  dir = mkdtempSync(join(tmpdir(), "lgtm-lh-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Shape lighthouse's lhr.categories the way the runner reads it. */
function lhr(scores: Record<string, number>) {
  return {
    lhr: {
      categories: Object.fromEntries(
        Object.entries(scores).map(([k, score]) => [k, { title: k, score }]),
      ),
    },
  };
}

function ctx(auth?: { path: string }): RunnerContext {
  const baseUrl = "https://example.com";
  const site: SiteConfig = {
    name: "site",
    baseUrl,
    routes: [],
    auth: auth ? { type: "storageState", path: auth.path } : { type: "none" },
    failOn: "high",
  };
  return {
    site,
    run: { baseUrl, isLocalhost: false, allowActive: false, outDir: "", stamp: "" },
    urls: [baseUrl],
    caps: { docker: false, browser: true },
    log: () => {},
  };
}

describe("lighthouse.ts — THRESHOLDS", () => {
  it("passes clean when every category is exactly at its threshold (0.8 / 0.9 / 0.9)", async () => {
    // Exactly-at-threshold: the check is `score < threshold`, so a score equal
    // to the threshold must NOT be a finding.
    lighthouseMock.mockResolvedValue(
      lhr({ performance: 0.8, "best-practices": 0.9, seo: 0.9 }),
    );
    const r = await lighthouseRunner.run(ctx());
    expect(r.findings).toEqual([
      expect.objectContaining({ id: "lh-ok", severity: "info" }),
    ]);
  });

  it("flags each category that falls just below its own threshold", async () => {
    lighthouseMock.mockResolvedValue(
      lhr({ performance: 0.79, "best-practices": 0.89, seo: 0.89 }),
    );
    const r = await lighthouseRunner.run(ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")).toBeDefined();
    expect(r.findings.find((f) => f.id === "lh-best-practices")).toBeDefined();
    expect(r.findings.find((f) => f.id === "lh-seo")).toBeDefined();
  });

  it("applies the performance threshold (0.8), not the stricter 0.9 — a 0.85 perf score is fine but a 0.85 SEO score is not", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0.85, seo: 0.85 }));
    const r = await lighthouseRunner.run(ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")).toBeUndefined();
    expect(r.findings.find((f) => f.id === "lh-seo")).toBeDefined();
  });

  it("ignores a category with no configured threshold (e.g. accessibility — a11y.ts owns that)", async () => {
    lighthouseMock.mockResolvedValue(lhr({ accessibility: 0.1 }));
    const r = await lighthouseRunner.run(ctx());
    expect(r.findings.find((f) => f.id === "lh-accessibility")).toBeUndefined();
  });

  it("surfaces the raw scores in meta regardless of pass/fail", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0.42, seo: 1 }));
    const r = await lighthouseRunner.run(ctx());
    expect(r.meta?.scores).toEqual({ performance: 0.42, seo: 1 });
  });
});

describe("lighthouse.ts — SEVERITY_BY_SCORE", () => {
  it("scores below 0.5 are medium; 0.5 and above are low", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0.49, seo: 0.5 }));
    const r = await lighthouseRunner.run(ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")!.severity).toBe("medium");
    expect(r.findings.find((f) => f.id === "lh-seo")!.severity).toBe("low");
  });

  it("a catastrophic 0 score is medium (the mapping tops out there)", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0 }));
    const r = await lighthouseRunner.run(ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")!.severity).toBe("medium");
  });
});

describe("lighthouse.ts — cookieHeaderFrom (authed scoring)", () => {
  function writeState(cookies: Array<{ name: string; value: string; domain: string }>) {
    const p = join(dir, "state.json");
    writeFileSync(p, JSON.stringify({ cookies }));
    return p;
  }

  /** The Cookie header the runner passed to lighthouse, if any. */
  function sentCookie(): string | undefined {
    const opts = lighthouseMock.mock.calls[0]?.[1] as
      | { extraHeaders?: Record<string, string> }
      | undefined;
    return opts?.extraHeaders?.["Cookie"];
  }

  it("sends matching cookies as a Cookie header so the authed page is what gets scored", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    const p = writeState([
      { name: "session", value: "abc", domain: "example.com" },
      { name: "theme", value: "dark", domain: ".example.com" }, // leading-dot form
    ]);
    await lighthouseRunner.run(ctx({ path: p }));
    expect(sentCookie()).toBe("session=abc; theme=dark");
  });

  it("does not leak cookies scoped to a different domain into the request", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    const p = writeState([{ name: "other", value: "xyz", domain: "attacker.test" }]);
    await lighthouseRunner.run(ctx({ path: p }));
    expect(sentCookie()).toBeUndefined();
  });

  it("sends no Cookie header when the storageState file does not exist", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    await lighthouseRunner.run(ctx({ path: join(dir, "missing.json") }));
    expect(sentCookie()).toBeUndefined();
  });

  it("sends no Cookie header when the storageState file is corrupt, rather than throwing", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    const p = join(dir, "bad.json");
    writeFileSync(p, "{ not json");
    const r = await lighthouseRunner.run(ctx({ path: p }));
    expect(sentCookie()).toBeUndefined();
    expect(r.status).toBe("ok");
  });

  it("sends no Cookie header for an unauthenticated site config", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    await lighthouseRunner.run(ctx());
    expect(sentCookie()).toBeUndefined();
  });
});

describe("lighthouse.ts — failure modes", () => {
  it("errors (not silently passes) when Chrome cannot be launched", async () => {
    launchMock.mockRejectedValue(new Error("no chrome"));
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/could not launch Chrome/i);
    expect(r.findings).toEqual([]);
  });

  it("errors when lighthouse itself throws", async () => {
    lighthouseMock.mockRejectedValue(new Error("lh exploded"));
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/lh exploded/);
  });

  // Lighthouse's contract is `Promise<RunnerResult | undefined>`: it can resolve
  // with NOTHING, without throwing. That path used to skip the whole scoring loop
  // and land in the empty-findings branch, which reports "scores meet thresholds".
  // A scan that measured nothing was reported as a scan that passed.
  it.each([
    ["resolves undefined", undefined],
    ["resolves without an lhr", {}],
    ["resolves with an lhr but no categories", { lhr: {} }],
  ])(
    "errors (never reports a clean pass) when lighthouse %s",
    async (_label, resolved) => {
      lighthouseMock.mockResolvedValue(resolved);
      const r = await lighthouseRunner.run(ctx());
      expect(r.status).toBe("error");
      expect(r.findings).toEqual([]);
      expect(r.findings.map((f) => f.id)).not.toContain("lh-ok");
      expect(r.note).toMatch(/unknown, not passing/i);
    },
  );
});

// ── 42L-1003: an unmeasured page is not a page that scored zero ─────────────
// The empty-lhr guard above only catches the case where Lighthouse hands back
// nothing. It does NOT catch the far commoner one: a page that failed to render
// comes back with `categories` PRESENT and every `score: null`, plus a
// `runtimeError` nobody read. `score ?? 0` then turned "unmeasured" into
// "measured zero" — three findings at `medium`, which sail straight past the
// default `failOn: "high"`. A dead page scored as a passing performance audit.
describe("lighthouseRunner — an unmeasured page is never a passing page (42L-1003)", () => {
  const NULL_SCORES = {
    lhr: {
      categories: {
        performance: { title: "Performance", score: null },
        "best-practices": { title: "Best Practices", score: null },
        seo: { title: "SEO", score: null },
      },
    },
  };

  it.each([
    ["NO_FCP", "The page did not paint any content"],
    ["ERRORED_DOCUMENT_REQUEST", "Lighthouse could not reliably load the page"],
    ["PROTOCOL_TIMEOUT", "Waiting for DevTools protocol response has exceeded"],
  ])("errors when lighthouse reports runtimeError %s", async (code, message) => {
    lighthouseMock.mockResolvedValue({
      lhr: { ...NULL_SCORES.lhr, runtimeError: { code, message } },
    });
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    expect(r.note).toMatch(new RegExp(code));
    expect(r.note).toMatch(/unknown, not passing/i);
  });

  it("errors when every category came back unscored, even with no runtimeError", async () => {
    lighthouseMock.mockResolvedValue(NULL_SCORES);
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    expect(r.note).toMatch(/unknown, not passing/i);
  });

  it("never coerces a null score to 0 — the old bug produced medium findings that PASSED", async () => {
    // The precise regression: null → 0 → below every threshold → three findings,
    // all `medium` (SEVERITY_BY_SCORE(0) < 0.5), none of which reach the default
    // failOn: "high". The run passed. It must now refuse instead.
    lighthouseMock.mockResolvedValue(NULL_SCORES);
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).not.toBe("ok");
    expect(r.findings.filter((f) => f.severity === "medium")).toHaveLength(0);
    expect(r.findings.map((f) => f.id)).not.toContain("lh-performance");
  });

  // We pin exactly three categories via onlyCategories, so all three must come
  // back scored. Skipping the null one and scoring the rest would report
  // "scores meet thresholds" for a category that was never measured — the same
  // lie, one level down. A partially-measured page is not a passing page.
  it("refuses when only SOME categories are unscored", async () => {
    lighthouseMock.mockResolvedValue({
      lhr: {
        categories: {
          performance: { title: "Performance", score: 0.95 },
          "best-practices": { title: "Best Practices", score: null },
          seo: { title: "SEO", score: 0.95 },
        },
      },
    });
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/best-practices/);
    expect(r.note).toMatch(/unknown, not passing/i);
    // The old bug's signature: two good scores carrying a green pass.
    expect(r.findings.map((f) => f.id)).not.toContain("lh-ok");
  });

  it("scores normally when all three categories came back measured", async () => {
    lighthouseMock.mockResolvedValue(
      lhr({ performance: 0.42, "best-practices": 0.95, seo: 0.95 }),
    );
    const r = await lighthouseRunner.run(ctx());
    expect(r.status).toBe("ok");
    // performance 0.42 < 0.8 → a real finding, at medium (score < 0.5).
    expect(r.findings.find((f) => f.id === "lh-performance")?.severity).toBe("medium");
    expect(r.findings.map((f) => f.id)).not.toContain("lh-seo");
  });
});
