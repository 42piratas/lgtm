import { describe, it, expect, vi, beforeEach } from "vitest";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Runner, RunnerContext, RunnerResult, SiteConfig } from "../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The orchestrator's gate() decides which runners actually execute. Every
// bug class in this ticket that isn't a pure-scoring bug traces back to a
// runner running when it shouldn't (or silently not running at all):
//   - white-box runners need repoPath — skip must be visible, not a silent
//     empty "clean" result an operator mistakes for a pass.
//   - docker-hosted scanners must not crash the whole audit when Docker is
//     down; they must report a legible skip.
//   - localhost-only (active/mutating) runners must never fire at a remote
//     target.
// These are tested through the real orchestrator against fake runners, so
// gate()'s actual decision logic is exercised — not a re-description of it.

vi.mock("../src/util/docker.js", () => ({
  hasDocker: vi.fn(),
}));

const { hasDocker } = await import("../src/util/docker.js");

let fakeRunners: Runner[] = [];
vi.mock("../src/runners/index.js", () => ({
  get ALL_RUNNERS() {
    return fakeRunners;
  },
  runnerById: (id: string) => fakeRunners.find((r) => r.id === id),
}));

const { runAudit } = await import("../src/orchestrator.js");

function baseSite(overrides: Partial<SiteConfig> = {}): SiteConfig {
  return {
    name: "site",
    baseUrl: "https://example.com",
    routes: [],
    auth: { type: "none" },
    failOn: "high",
    ...overrides,
  };
}

function okRunner(id: string, run: Runner["run"]): Runner {
  return { id, domain: "security", title: id, requires: {}, run };
}

beforeEach(() => {
  fakeRunners = [];
  vi.mocked(hasDocker).mockReset();
});

describe("gate — white-box runners without a repo checkout", () => {
  it("skips visibly (not silently) when repoPath is not configured", async () => {
    const run = vi.fn();
    fakeRunners = [
      { id: "deps", domain: "deps", title: "deps", requires: { repo: true }, run },
    ];
    const logs: string[] = [];
    const report = await runAudit({
      site: baseSite(), // no repoPath
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
      log: (m) => logs.push(m),
    });

    expect(run).not.toHaveBeenCalled();
    const r = report.results.find((x) => x.runnerId === "deps")!;
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/no repoPath configured/i);
    // Visible: the skip is surfaced through the log callback an operator sees.
    expect(logs.some((l) => l.includes("deps") && /skip/i.test(l))).toBe(true);
  });

  it("skips when repoPath is configured but doesn't exist on disk", async () => {
    const run = vi.fn();
    fakeRunners = [
      { id: "secrets", domain: "secrets", title: "secrets", requires: { repo: true }, run },
    ];
    const report = await runAudit({
      site: baseSite({ repoPath: "/definitely/not/a/real/path/on/this/box" }),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
    });
    expect(run).not.toHaveBeenCalled();
    const r = report.results.find((x) => x.runnerId === "secrets")!;
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/does not exist/i);
  });

  it("runs a white-box runner once repoPath exists (using this test file's own directory as a stand-in repo)", async () => {
    const run = vi.fn(async (ctx: RunnerContext): Promise<RunnerResult> => ({
      runnerId: "secrets",
      domain: "secrets",
      status: "ok",
      findings: [],
      durationMs: 1,
    }));
    fakeRunners = [
      { id: "secrets", domain: "secrets", title: "secrets", requires: { repo: true }, run },
    ];
    await runAudit({
      site: baseSite({ repoPath: HERE }),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
    });
    expect(run).toHaveBeenCalledTimes(1);
  });
});

describe("gate — localhost-only runners", () => {
  it("skips an active/mutating runner against a remote target", async () => {
    const run = vi.fn();
    fakeRunners = [
      {
        id: "zap-active",
        domain: "dast",
        title: "zap",
        requires: { localhostOnly: true },
        run,
      },
    ];
    const report = await runAudit({
      site: baseSite(),
      baseUrl: "https://example.com", // remote
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: true, // operator opted in, but target still isn't localhost
    });
    expect(run).not.toHaveBeenCalled();
    const r = report.results.find((x) => x.runnerId === "zap-active")!;
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/localhost-only/i);
  });

  it("runs a localhost-only runner against a localhost target", async () => {
    const run = vi.fn(async (): Promise<RunnerResult> => ({
      runnerId: "zap-active",
      domain: "dast",
      status: "ok",
      findings: [],
      durationMs: 1,
    }));
    fakeRunners = [
      {
        id: "zap-active",
        domain: "dast",
        title: "zap",
        requires: { localhostOnly: true },
        run,
      },
    ];
    await runAudit({
      site: baseSite({ baseUrl: "http://localhost:3000" }),
      baseUrl: "http://localhost:3000",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: true,
    });
    expect(run).toHaveBeenCalledTimes(1);
  });
});

describe("docker-hosted runners: visible skip, not a crash, when Docker is down", () => {
  it("surfaces a legible skipped result via the orchestrator-resolved capability, instead of throwing", async () => {
    vi.mocked(hasDocker).mockResolvedValue(false);
    // Mirrors the real pattern used by tls/deps/secrets/sast/zap: the runner
    // itself checks capability and returns a skip — gate() does not special
    // case `requires.docker`, so this must hold at the runner level.
    const run = vi.fn(async (ctx: RunnerContext): Promise<RunnerResult> => {
      if (!ctx.caps.docker) {
        return {
          runnerId: "tls",
          domain: "transport",
          status: "skipped",
          note: "docker unavailable (testssl.sh image needs it)",
          findings: [],
          durationMs: 0,
        };
      }
      throw new Error("should not reach here in this test");
    });
    fakeRunners = [
      { id: "tls", domain: "transport", title: "tls", requires: { docker: true }, run },
    ];
    const report = await runAudit({
      site: baseSite(),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
    });
    const r = report.results.find((x) => x.runnerId === "tls")!;
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
    expect(report.passed).toBe(true); // a skip must never itself fail the gate
  });
});

describe("runner crashes are caught, not fatal to the whole audit", () => {
  it("turns a thrown error into a status: error result and keeps going", async () => {
    fakeRunners = [
      okRunner("boom", async () => {
        throw new Error("kaboom");
      }),
      okRunner("after", async () => ({
        runnerId: "after",
        domain: "security",
        status: "ok",
        findings: [],
        durationMs: 1,
      })),
    ];
    const report = await runAudit({
      site: baseSite(),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
    });
    expect(report.results).toHaveLength(2);
    const boom = report.results.find((r) => r.runnerId === "boom")!;
    expect(boom.status).toBe("error");
    expect(boom.note).toMatch(/kaboom/);
    const after = report.results.find((r) => r.runnerId === "after")!;
    expect(after.status).toBe("ok");
  });
});

describe("--only and site.skip selection", () => {
  it("--only runs exclusively the named runners", async () => {
    const a = vi.fn(async () => ({ runnerId: "a", domain: "security" as const, status: "ok" as const, findings: [], durationMs: 1 }));
    const b = vi.fn(async () => ({ runnerId: "b", domain: "security" as const, status: "ok" as const, findings: [], durationMs: 1 }));
    fakeRunners = [okRunner("a", a), okRunner("b", b)];
    const report = await runAudit({
      site: baseSite(),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
      only: ["a"],
    });
    expect(a).toHaveBeenCalled();
    expect(b).not.toHaveBeenCalled();
    expect(report.results.map((r) => r.runnerId)).toEqual(["a"]);
  });

  it("site.skip removes runners from the default (non---only) selection", async () => {
    const a = vi.fn(async () => ({ runnerId: "a", domain: "security" as const, status: "ok" as const, findings: [], durationMs: 1 }));
    const b = vi.fn(async () => ({ runnerId: "b", domain: "security" as const, status: "ok" as const, findings: [], durationMs: 1 }));
    fakeRunners = [okRunner("a", a), okRunner("b", b)];
    await runAudit({
      site: baseSite({ skip: ["b"] }),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
    });
    expect(a).toHaveBeenCalled();
    expect(b).not.toHaveBeenCalled();
  });
});

describe("AuditReport shape — the contract CI consumes", () => {
  it("wires totals/passed/failOn from the actual results, not independently", async () => {
    fakeRunners = [
      okRunner("clean", async () => ({
        runnerId: "clean",
        domain: "security",
        status: "ok",
        findings: [{ id: "ok", title: "ok", severity: "info" }],
        durationMs: 1,
      })),
      okRunner("bad", async () => ({
        runnerId: "bad",
        domain: "security",
        status: "ok",
        findings: [{ id: "leak", title: "leak", severity: "critical" }],
        durationMs: 1,
      })),
    ];
    const report = await runAudit({
      site: baseSite({ failOn: "high" }),
      baseUrl: "https://example.com",
      outDir: "/tmp/unused",
      stamp: "x",
      allowActive: false,
    });
    expect(report.totals).toEqual({ critical: 1, high: 0, medium: 0, low: 0, info: 1 });
    expect(report.failOn).toBe("high");
    expect(report.passed).toBe(false);
    expect(report.site).toBe("site");
    expect(report.results).toHaveLength(2);
  });
});
