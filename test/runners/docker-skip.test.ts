import { describe, it, expect, vi, beforeEach } from "vitest";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// Every docker-hosted runner (tls, deps, secrets, sast, zap) self-checks
// hasDocker() and must return a *visible* skipped result — never throw,
// never silently report "clean" — when Docker is down. This is real
// production code from src/runners/*, exercised through each runner's
// public run(), with only util/docker.js's hasDocker mocked. No runner file
// is modified.

vi.mock("../../src/util/docker.js", () => ({
  hasDocker: vi.fn(),
  dockerRun: vi.fn(),
  containerReachableUrl: (u: string) => u,
}));

const { hasDocker } = await import("../../src/util/docker.js");
const { tlsRunner } = await import("../../src/runners/tls.js");
const { depsRunner } = await import("../../src/runners/deps.js");
const { secretsRunner } = await import("../../src/runners/secrets.js");
const { sastRunner } = await import("../../src/runners/sast.js");
const { zapRunner } = await import("../../src/runners/zap.js");

function ctx(overrides: Partial<{ baseUrl: string; repoPath?: string }> = {}): RunnerContext {
  const baseUrl = overrides.baseUrl ?? "https://example.com";
  const site: SiteConfig = {
    name: "site",
    baseUrl,
    repoPath: overrides.repoPath,
    routes: [],
    auth: { type: "none" },
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

beforeEach(() => {
  vi.mocked(hasDocker).mockReset();
  vi.mocked(hasDocker).mockResolvedValue(false);
});

describe("docker-hosted runners skip visibly when Docker is down", () => {
  it("tls: skips with a docker-specific note (given an https, non-local target so it gets past the TLS-applicability check)", async () => {
    const r = await tlsRunner.run(ctx({ baseUrl: "https://example.com" }));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
  });

  it("deps: skips with a docker-specific note", async () => {
    const r = await depsRunner.run(ctx({ repoPath: "/tmp/whatever" }));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
  });

  it("secrets: skips with a docker-specific note", async () => {
    const r = await secretsRunner.run(ctx({ repoPath: "/tmp/whatever" }));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
  });

  it("sast: skips with a docker-specific note", async () => {
    const r = await sastRunner.run(ctx({ repoPath: "/tmp/whatever" }));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
  });

  it("zap: skips with a docker-specific note", async () => {
    const r = await zapRunner.run(ctx());
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
  });

  it("none of these produce a passing/clean result while skipped — a skip must never masquerade as a pass", async () => {
    const results = await Promise.all([
      tlsRunner.run(ctx({ baseUrl: "https://example.com" })),
      depsRunner.run(ctx({ repoPath: "/tmp/whatever" })),
      secretsRunner.run(ctx({ repoPath: "/tmp/whatever" })),
      sastRunner.run(ctx({ repoPath: "/tmp/whatever" })),
      zapRunner.run(ctx()),
    ]);
    for (const r of results) {
      expect(r.status).toBe("skipped");
      expect(r.findings).toEqual([]); // no fabricated "ok" finding standing in for a real scan
    }
  });
});
