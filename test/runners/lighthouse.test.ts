import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { derive } from "../../src/scoring.js";
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

/**
 * Shape lighthouse's lhr the way the runner reads it.
 *
 * A real LHR NEVER has a category without auditRefs, or an auditRef without a
 * matching entry in `audits` — a score is an average over audits, so a scored
 * category that measured nothing is not a thing Lighthouse can emit. The
 * fixture has to obey that, or the tests end up certifying behaviour against a
 * report that could not exist, which is how the runner grew a false clean in
 * the first place. Each category here gets one weighted audit that produced a
 * value.
 */
function lhr(scores: Record<string, number>) {
  const keys = Object.keys(scores);
  return {
    lhr: {
      categories: Object.fromEntries(
        keys.map((k) => [
          k,
          {
            title: k,
            score: scores[k],
            auditRefs: [{ id: `${k}-audit`, weight: 1 }],
          },
        ]),
      ),
      audits: Object.fromEntries(
        keys.map((k) => [
          `${k}-audit`,
          { title: `${k} audit`, scoreDisplayMode: "numeric" },
        ]),
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
    const r = await derive(lighthouseRunner, ctx());
    // Clean is now the ABSENCE of findings backed by the presence of evidence —
    // never a self-declared "lh-ok" pass-note. The runner states what it
    // measured; the orchestrator decides that amounts to a pass.
    expect(r.findings).toEqual([]);
    expect(r.status).toBe("ok");
    expect(r.coverage?.data.categoriesScored).toBe(3);
  });

  it("flags each category that falls just below its own threshold", async () => {
    lighthouseMock.mockResolvedValue(
      lhr({ performance: 0.79, "best-practices": 0.89, seo: 0.89 }),
    );
    const r = await derive(lighthouseRunner, ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")).toBeDefined();
    expect(r.findings.find((f) => f.id === "lh-best-practices")).toBeDefined();
    expect(r.findings.find((f) => f.id === "lh-seo")).toBeDefined();
  });

  it("applies the performance threshold (0.8), not the stricter 0.9 — a 0.85 perf score is fine but a 0.85 SEO score is not", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0.85, seo: 0.85 }));
    const r = await derive(lighthouseRunner, ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")).toBeUndefined();
    expect(r.findings.find((f) => f.id === "lh-seo")).toBeDefined();
  });

  it("ignores a category with no configured threshold (e.g. accessibility — a11y.ts owns that)", async () => {
    lighthouseMock.mockResolvedValue(lhr({ accessibility: 0.1 }));
    const r = await derive(lighthouseRunner, ctx());
    expect(r.findings.find((f) => f.id === "lh-accessibility")).toBeUndefined();
  });

  it("surfaces the raw scores in meta regardless of pass/fail", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0.42, seo: 1 }));
    const r = await derive(lighthouseRunner, ctx());
    expect(r.meta?.scores).toEqual({ performance: 0.42, seo: 1 });
  });
});

describe("lighthouse.ts — SEVERITY_BY_SCORE", () => {
  it("scores below 0.5 are medium; 0.5 and above are low", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0.49, seo: 0.5 }));
    const r = await derive(lighthouseRunner, ctx());
    expect(r.findings.find((f) => f.id === "lh-performance")!.severity).toBe("medium");
    expect(r.findings.find((f) => f.id === "lh-seo")!.severity).toBe("low");
  });

  it("a catastrophic 0 score is medium (the mapping tops out there)", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 0 }));
    const r = await derive(lighthouseRunner, ctx());
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
    await derive(lighthouseRunner, ctx({ path: p }));
    expect(sentCookie()).toBe("session=abc; theme=dark");
  });

  it("does not leak cookies scoped to a different domain into the request", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    const p = writeState([{ name: "other", value: "xyz", domain: "attacker.test" }]);
    await derive(lighthouseRunner, ctx({ path: p }));
    expect(sentCookie()).toBeUndefined();
  });

  it("sends no Cookie header when the storageState file does not exist", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    await derive(lighthouseRunner, ctx({ path: join(dir, "missing.json") }));
    expect(sentCookie()).toBeUndefined();
  });

  it("sends no Cookie header when the storageState file is corrupt, rather than throwing", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    const p = join(dir, "bad.json");
    writeFileSync(p, "{ not json");
    const r = await derive(lighthouseRunner, ctx({ path: p }));
    expect(sentCookie()).toBeUndefined();
    expect(r.status).toBe("ok");
  });

  it("sends no Cookie header for an unauthenticated site config", async () => {
    lighthouseMock.mockResolvedValue(lhr({ performance: 1 }));
    await derive(lighthouseRunner, ctx());
    expect(sentCookie()).toBeUndefined();
  });
});

describe("lighthouse.ts — failure modes", () => {
  it("errors (not silently passes) when Chrome cannot be launched", async () => {
    launchMock.mockRejectedValue(new Error("no chrome"));
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/could not launch Chrome/i);
    expect(r.findings).toEqual([]);
  });

  it("errors when lighthouse itself throws", async () => {
    lighthouseMock.mockRejectedValue(new Error("lh exploded"));
    const r = await derive(lighthouseRunner, ctx());
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
      const r = await derive(lighthouseRunner, ctx());
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
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    expect(r.note).toMatch(new RegExp(code));
    expect(r.note).toMatch(/unknown, not passing/i);
  });

  it("errors when every category came back unscored, even with no runtimeError", async () => {
    lighthouseMock.mockResolvedValue(NULL_SCORES);
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    expect(r.note).toMatch(/unknown, not passing/i);
  });

  it("never coerces a null score to 0 — the old bug produced medium findings that PASSED", async () => {
    // The precise regression: null → 0 → below every threshold → three findings,
    // all `medium` (SEVERITY_BY_SCORE(0) < 0.5), none of which reach the default
    // failOn: "high". The run passed. It must now refuse instead.
    lighthouseMock.mockResolvedValue(NULL_SCORES);
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).not.toBe("ok");
    expect(r.findings.filter((f) => f.severity === "medium")).toHaveLength(0);
    expect(r.findings.map((f) => f.id)).not.toContain("lh-performance");
  });

  // A category's score goes null the moment ANY audit inside it is unscored
  // (Lighthouse's arithmeticMean returns null if a single item is null). So a
  // null category does NOT by itself mean the page wasn't measured — it can
  // equally mean one audit legitimately didn't apply.
  //
  // Lighthouse CI, Google's own build gate, draws the line by CAUSE: an audit
  // with scoreDisplayMode "notApplicable" counts as a pass; an audit that ran
  // and produced nothing is a hard failure ("Audit did not produce a value at
  // all"). We match that. Refusing on every null category instead would
  // red-build healthy sites — which is how a gate gets switched off.
  // Builds an LHR the way real Lighthouse emits one. Critically, it applies
  // Lighthouse's OWN scoring rules (core/scoring.js) rather than letting the
  // test invent a shape:
  //   - notApplicable / informative / manual audits get weight 0
  //   - arithmeticMean drops weight-0 items, THEN checks for null
  //   - `sum / weight || 0` — so an all-not-applicable category scores 0, NOT null
  // Getting this wrong is how a test ends up encoding the same wrong mental
  // model as the code it is supposed to be guarding.
  const ZERO_WEIGHT = new Set(["notApplicable", "informative", "manual"]);

  function withAudits(
    cats: Record<string, string[]>,
    audits: Record<string, { scoreDisplayMode: string; title: string; score: number | null }>,
  ) {
    const audit = (id: string) => {
      const a = audits[id];
      if (!a) throw new Error(`test fixture: no audit "${id}"`);
      return a;
    };
    const categories = Object.fromEntries(
      Object.entries(cats).map(([key, refIds]) => {
        const refs = refIds.map((id) => ({
          id,
          weight: ZERO_WEIGHT.has(audit(id).scoreDisplayMode) ? 0 : 1,
        }));
        const weighted = refs.filter((r) => r.weight > 0);
        let score: number | null;
        if (weighted.some((r) => audit(r.id).score === null)) {
          score = null; // a weighted null (an errored audit) nulls the category
        } else {
          const sum = weighted.reduce((a, r) => a + (audit(r.id).score as number) * r.weight, 0);
          const w = weighted.reduce((a, r) => a + r.weight, 0);
          score = sum / w || 0; // 0/0 → NaN → || 0 — the all-not-applicable case
        }
        return [key, { title: key, score, auditRefs: refs }];
      }),
    );
    return { lhr: { audits, categories } };
  }

  const OK_AUDITS = {
    fcp: { scoreDisplayMode: "numeric", title: "First Contentful Paint", score: 0.95 },
    viewport: { scoreDisplayMode: "binary", title: "Has a viewport meta tag", score: 0.95 },
    "image-alt": {
      scoreDisplayMode: "notApplicable",
      title: "Images have alt text",
      score: null,
    },
    "is-on-https": { scoreDisplayMode: "error", title: "Uses HTTPS", score: null },
  };

  it("refuses when a category is unscored because an audit ERRORED", async () => {
    lighthouseMock.mockResolvedValue(
      withAudits(
        {
          performance: ["fcp"],
          "best-practices": ["is-on-https"], // errored, weight 1 → category null
          seo: ["viewport"],
        },
        OK_AUDITS,
      ),
    );
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/best-practices/);
    expect(r.note).toMatch(/unknown, not passing/i);
    expect(r.findings.map((f) => f.id)).not.toContain("lh-ok");
  });

  // The case the previous attempt got wrong. Real Lighthouse zeroes the weight of
  // a notApplicable audit, so a category made entirely of them does NOT come back
  // null — it comes back **0** (`0/0 || 0`). Scoring that 0 against the threshold
  // reports a failing grade for a category that was never measured: the `?? 0`
  // bug again, one layer down. It must be surfaced, never graded.
  it("never grades the 0 that an all-not-applicable category comes back with", async () => {
    lighthouseMock.mockResolvedValue(
      withAudits(
        {
          performance: ["fcp"],
          "best-practices": ["image-alt"], // notApplicable → weight 0 → score 0, not null
          seo: ["viewport"],
        },
        OK_AUDITS,
      ),
    );
    const r = await derive(lighthouseRunner, ctx());

    // Sanity-check the fixture really reproduces Lighthouse's behaviour: an
    // all-not-applicable category scores 0, not null. If this ever asserts null,
    // the fixture — not the runner — is the thing that drifted.
    const lhrCats = (await lighthouseMock.mock.results[0]?.value).lhr.categories as Record<
      string,
      { score: number | null }
    >;
    expect(lhrCats["best-practices"]?.score).toBe(0);

    expect(r.status).toBe("ok");
    // The 0 must NOT have become a threshold failure.
    expect(r.findings.map((f) => f.id)).not.toContain("lh-best-practices");
    // It must be visible as "no verdict", not silently dropped.
    expect(
      r.findings.find((f) => f.id === "lh-best-practices-not-measured")?.needsReview,
    ).toBe(true);
    expect(r.findings.map((f) => f.id)).not.toContain("lh-ok");
    expect((r.meta as { scores: Record<string, number> }).scores).not.toHaveProperty(
      "best-practices",
    );
  });

  it("refuses when NO category scored at all, even with nothing errored", async () => {
    lighthouseMock.mockResolvedValue(
      withAudits(
        {
          performance: ["image-alt"],
          "best-practices": ["image-alt"],
          seo: ["image-alt"],
        },
        OK_AUDITS,
      ),
    );
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/never measured/i);
  });

  it("does not refuse for an errored audit that carries no weight", async () => {
    // A zero-weight errored audit doesn't null the category and doesn't affect
    // the score — failing the whole run on it would be crying wolf.
    lighthouseMock.mockResolvedValue({
      lhr: {
        audits: OK_AUDITS,
        categories: {
          performance: {
            title: "performance",
            score: 0.95,
            auditRefs: [
              { id: "fcp", weight: 1 },
              { id: "is-on-https", weight: 0 },
            ],
          },
        },
      },
    });
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("ok");
  });

  it("scores normally when all three categories came back measured", async () => {
    lighthouseMock.mockResolvedValue(
      lhr({ performance: 0.42, "best-practices": 0.95, seo: 0.95 }),
    );
    const r = await derive(lighthouseRunner, ctx());
    expect(r.status).toBe("ok");
    // performance 0.42 < 0.8 → a real finding, at medium (score < 0.5).
    expect(r.findings.find((f) => f.id === "lh-performance")?.severity).toBe("medium");
    expect(r.findings.map((f) => f.id)).not.toContain("lh-seo");
  });
});
