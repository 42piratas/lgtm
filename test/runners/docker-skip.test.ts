import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SiteConfig } from "../../src/types.js";

// Every docker-hosted runner (tls, deps, secrets, sast, zap) needs a Docker
// daemon. That requirement is declared once, in `requires`, and enforced once,
// in the orchestrator's gate — the runners no longer each re-implement the
// check (and no longer each get to decide what a missing daemon means).
//
// Two things must hold when Docker is down:
//   1. Each of those runners is visibly skipped — never a crash, and never a
//      fabricated "clean".
//   2. The RUN FAILS. Five security domains going unaudited is a coverage hole,
//      not a detail: a green build on a machine with no Docker would certify a
//      dependency tree, a secret history and a codebase nobody scanned.

vi.mock("../../src/util/docker.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/util/docker.js")>();
  return { ...actual, hasDocker: vi.fn(), dockerRun: vi.fn() };
});

// The suite must never reach the network: with Docker down we skip before any
// runner would fetch, but a future reordering must not turn this file into one
// that needs the internet.
vi.mock("../../src/util/authgate.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/util/authgate.js")>();
  return { ...actual, probeTarget: async () => ({ ok: false, note: "stubbed" }) };
});
vi.mock("../../src/util/http.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/util/http.js")>();
  return { ...actual, fetchUrl: async () => { throw new Error("stubbed"); } };
});
vi.mock("playwright", () => ({
  chromium: { launch: async () => { throw new Error("stubbed"); } },
}));

const { hasDocker } = await import("../../src/util/docker.js");
const { runAudit } = await import("../../src/orchestrator.js");

const DOCKER_RUNNERS = ["tls", "deps", "secrets", "sast", "zap"];

let repo: string;

beforeEach(() => {
  vi.mocked(hasDocker).mockReset();
  vi.mocked(hasDocker).mockResolvedValue(false);
  repo = mkdtempSync(join(tmpdir(), "lgtm-repo-"));
});

function site(): SiteConfig {
  return {
    name: "site",
    baseUrl: "https://example.com",
    repoPath: repo,
    routes: [],
    auth: { type: "none" },
    failOn: "high",
  };
}

async function audit(only?: string[]) {
  const s = site();
  return runAudit({
    site: s,
    baseUrl: s.baseUrl,
    outDir: "",
    stamp: "t",
    allowActive: false,
    only,
  });
}

describe("docker-hosted runners are gated, not crashed, when Docker is down", () => {
  it.each(DOCKER_RUNNERS)(
    "%s: skipped with a docker-specific reason, and no fabricated findings",
    async (id) => {
      const report = await audit([id]);
      const r = report.results.find((x) => x.runnerId === id)!;
      expect(r.status).toBe("skipped");
      expect(r.note).toMatch(/docker unavailable/i);
      expect(r.findings).toEqual([]);
      rmSync(repo, { recursive: true, force: true });
    },
  );

  it("a skip is never a pass — the run FAILS, because those domains went unaudited", async () => {
    const report = await audit(DOCKER_RUNNERS);
    expect(report.complete).toBe(false);
    expect(report.passed).toBe(false);
    // Every one of them is named as a hole, not quietly waived.
    const holes = report.notAudited.filter((n) => !n.waived).map((n) => n.runnerId);
    expect(holes.sort()).toEqual([...DOCKER_RUNNERS].sort());
    rmSync(repo, { recursive: true, force: true });
  });
});
