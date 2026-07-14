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
