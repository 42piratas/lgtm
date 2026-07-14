import { describe, it, expect, vi, beforeEach } from "vitest";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  Coverage,
  Domain,
  Runner,
  RunnerOutcome,
  SiteConfig,
} from "../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The orchestrator is where a scan becomes a VERDICT. Everything that decides
// whether lgtm may call a domain clean lives here:
//
//   gate()      — which runners are even allowed to run, and what it means when
//                 one cannot: a domain that does not apply (no TLS on an http
//                 dev server) is not the same as a domain nobody audited (no
//                 Docker, no repo checkout). The first is fine; the second is a
//                 coverage hole and must fail the run.
//   derive()    — turns an observation into a status by asking the runner's own
//                 sufficient() rule whether the evidence supports a conclusion.
//                 A runner cannot set its own status: RunnerOutcome has no
//                 status field. That is the whole point of the contract.
//   complete    — a run that never audited half its domains cannot pass, no
//                 matter how few findings it has.
//
// Tested through the real orchestrator against fake runners, so the actual
// decision logic is exercised rather than re-described.

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

/** Coverage that any sufficiency rule would accept — "we really did look". */
const LOOKED: Coverage = {
  trail: ["looked at the thing"],
  data: { looked: 1 },
  provenance: "test",
};

/**
 * A fake runner. `sufficient` defaults to permissive so a test can isolate the
 * gate; tests about evidence supply their own.
 */
function fake(
  id: string,
  observe: Runner["observe"],
  opts: {
    requires?: Runner["requires"];
    domain?: Domain;
    sufficient?: Runner["sufficient"];
  } = {},
): Runner {
  return {
    id,
    domain: opts.domain ?? "security",
    title: id,
    requires: opts.requires ?? {},
    observe,
    sufficient: opts.sufficient ?? (() => null),
  };
}

/** The ordinary "ran, saw nothing wrong, and can prove it looked" outcome. */
const cleanObserve = async (): Promise<RunnerOutcome> => ({
  kind: "observed",
  findings: [],
  coverage: LOOKED,
});

async function audit(opts: {
  site?: SiteConfig;
  baseUrl?: string;
  allowActive?: boolean;
  only?: string[];
  log?: (m: string) => void;
}) {
  const site = opts.site ?? baseSite();
  return runAudit({
    site,
    baseUrl: opts.baseUrl ?? site.baseUrl,
    outDir: "/tmp/unused",
    stamp: "x",
    allowActive: opts.allowActive ?? false,
    only: opts.only,
    log: opts.log,
  });
}

beforeEach(() => {
  fakeRunners = [];
  vi.mocked(hasDocker).mockReset();
  vi.mocked(hasDocker).mockResolvedValue(true);
});

describe("gate — white-box runners without a repo checkout", () => {
  it("skips visibly (not silently) when repoPath is not configured, and FAILS the run — that domain went unaudited", async () => {
    const observe = vi.fn();
    fakeRunners = [fake("deps", observe, { requires: { repo: true }, domain: "deps" })];
    const logs: string[] = [];
    const report = await audit({ log: (m) => logs.push(m) }); // no repoPath

    expect(observe).not.toHaveBeenCalled();
    const r = report.results.find((x) => x.runnerId === "deps")!;
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/no repoPath configured/i);
    // Visible: surfaced through the log callback an operator sees…
    expect(logs.some((l) => l.includes("deps") && /skip/i.test(l))).toBe(true);
    // …and consequential. Nobody scanned the dependencies; the run cannot pass.
    expect(report.complete).toBe(false);
    expect(report.passed).toBe(false);
    expect(report.notAudited).toContainEqual(
      expect.objectContaining({ runnerId: "deps", waived: false }),
    );
  });

  it("skips when repoPath is configured but doesn't exist on disk", async () => {
    const observe = vi.fn();
    fakeRunners = [
      fake("secrets", observe, { requires: { repo: true }, domain: "secrets" }),
    ];
    const report = await audit({
      site: baseSite({ repoPath: "/definitely/not/a/real/path/on/this/box" }),
    });
    expect(observe).not.toHaveBeenCalled();
    const r = report.results.find((x) => x.runnerId === "secrets")!;
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/does not exist/i);
    expect(report.passed).toBe(false);
  });

  it("runs a white-box runner once repoPath exists (using this test file's own directory as a stand-in repo)", async () => {
    const observe = vi.fn(cleanObserve);
    fakeRunners = [
      fake("secrets", observe, { requires: { repo: true }, domain: "secrets" }),
    ];
    const report = await audit({ site: baseSite({ repoPath: HERE }) });
    expect(observe).toHaveBeenCalledTimes(1);
    expect(report.passed).toBe(true);
  });
});

describe("gate — Docker, declared once and enforced once", () => {
  it("skips a docker-hosted runner when Docker is down, and FAILS the run — the runner no longer has to check for itself", async () => {
    vi.mocked(hasDocker).mockResolvedValue(false);
    const observe = vi.fn();
    fakeRunners = [
      fake("tls", observe, { requires: { docker: true }, domain: "transport" }),
    ];
    const report = await audit({});
    const r = report.results.find((x) => x.runnerId === "tls")!;
    expect(observe).not.toHaveBeenCalled();
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/docker unavailable/i);
    // The old behaviour: `expect(report.passed).toBe(true)` — "a skip must never
    // itself fail the gate". That was the bug one level up. A skipped scanner
    // means an unscanned domain, and an unscanned domain is not a clean one.
    expect(report.passed).toBe(false);
  });
});

describe("gate — not applicable is not the same as not audited", () => {
  it("a localhost-only probe against a remote target is NOT a coverage hole — nothing was missed", async () => {
    const observe = vi.fn();
    fakeRunners = [
      fake("zap-active", observe, { requires: { localhostOnly: true }, domain: "dast" }),
    ];
    const report = await audit({ allowActive: true }); // remote target
    const r = report.results.find((x) => x.runnerId === "zap-active")!;
    expect(observe).not.toHaveBeenCalled();
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/only runs against localhost/i);
    // Excused: an active scan has nothing to say about a target it must not
    // touch. The run can still pass.
    expect(report.complete).toBe(true);
    expect(report.passed).toBe(true);
  });

  it("runs a localhost-only runner against a localhost target", async () => {
    const observe = vi.fn(cleanObserve);
    fakeRunners = [
      fake("zap-active", observe, { requires: { localhostOnly: true }, domain: "dast" }),
    ];
    await audit({
      site: baseSite({ baseUrl: "http://localhost:3000" }),
      baseUrl: "http://localhost:3000",
      allowActive: true,
    });
    expect(observe).toHaveBeenCalledTimes(1);
  });

  it("a runner that declares itself notApplicable is excused; one that declares itself unavailable is not", async () => {
    fakeRunners = [
      fake("no-tls-here", async () => ({
        kind: "notApplicable",
        note: "no TLS to inspect (http/localhost target)",
      })),
      fake("cant-run", async () => ({
        kind: "unavailable",
        note: "auth storageState file missing",
      })),
    ];
    const report = await audit({});
    const na = report.notAudited.find((n) => n.runnerId === "no-tls-here")!;
    const hole = report.notAudited.find((n) => n.runnerId === "cant-run")!;
    expect(na.waived).toBe(true);
    expect(hole.waived).toBe(false);
    expect(report.complete).toBe(false);
    expect(report.passed).toBe(false);
  });
});

describe("derive — the runner reports evidence; the orchestrator reaches the verdict", () => {
  it("calls the runner's sufficient() with the coverage it reported, and passes when it is satisfied", async () => {
    const sufficient = vi.fn(() => null);
    fakeRunners = [fake("headers", cleanObserve, { sufficient })];
    const report = await audit({});
    expect(sufficient).toHaveBeenCalledWith(LOOKED, expect.anything());
    expect(report.results[0]!.status).toBe("ok");
    expect(report.results[0]!.coverage).toEqual(LOOKED);
    expect(report.passed).toBe(true);
  });

  it("REFUSES — status error, not a clean pass — when the evidence is too thin, even with zero findings", async () => {
    // This is the whole ticket. Under the old contract this runner returned
    // `status: "ok"` with an empty findings array and the report went green.
    fakeRunners = [
      fake(
        "deps",
        async () => ({
          kind: "observed",
          findings: [],
          coverage: { trail: [], data: { sources: 0 }, provenance: "walk log" },
        }),
        { sufficient: () => "no lockfiles were walked" },
      ),
    ];
    const report = await audit({});
    const r = report.results[0]!;
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/insufficient evidence — no lockfiles were walked/);
    expect(r.findings).toEqual([]);
    expect(report.passed).toBe(false);
  });

  it("keeps the findings a refused runner DID observe — a nav failure removes certainty, it does not erase evidence", async () => {
    fakeRunners = [
      fake(
        "authz",
        async () => ({
          kind: "observed",
          findings: [
            { id: "authz-open", title: "route wide open", severity: "high" as const },
          ],
          coverage: { trail: [], data: { probesFailed: 1 }, provenance: "probe" },
        }),
        { sufficient: () => "1 probe never landed" },
      ),
    ];
    const report = await audit({});
    const r = report.results[0]!;
    expect(r.status).toBe("error");
    expect(r.findings).toHaveLength(1);
    // And the tallies agree with the section — the report cannot contradict itself.
    expect(report.totals.high).toBe(1);
  });

  it("a runner cannot fabricate a pass: sufficient() is consulted even when it reported no findings and no note", async () => {
    const sufficient = vi.fn(() => "nothing was actually examined");
    fakeRunners = [fake("sast", cleanObserve, { sufficient })];
    const report = await audit({});
    expect(sufficient).toHaveBeenCalledTimes(1);
    expect(report.results[0]!.status).toBe("error");
  });
});

describe("runner crashes are caught, not fatal to the whole audit", () => {
  it("turns a thrown error into a status: error result and keeps going", async () => {
    fakeRunners = [
      fake("boom", async () => {
        throw new Error("kaboom");
      }),
      fake("after", cleanObserve),
    ];
    const report = await audit({});
    expect(report.results).toHaveLength(2);
    const boom = report.results.find((r) => r.runnerId === "boom")!;
    expect(boom.status).toBe("error");
    expect(boom.note).toMatch(/kaboom/);
    const after = report.results.find((r) => r.runnerId === "after")!;
    expect(after.status).toBe("ok");
  });
});

describe("--only and site.skip — a waiver is a decision, and it stays on the record", () => {
  it("--only runs exclusively the named runners, and reports the rest as waived rather than dropping them", async () => {
    const a = vi.fn(cleanObserve);
    const b = vi.fn(cleanObserve);
    fakeRunners = [fake("a", a), fake("b", b)];
    const report = await audit({ only: ["a"] });
    expect(a).toHaveBeenCalled();
    expect(b).not.toHaveBeenCalled();
    // b is still in the report — silently vanishing from the results is how a
    // partial run comes to look like a whole one.
    expect(report.results.map((r) => r.runnerId)).toEqual(["a", "b"]);
    expect(report.results.find((r) => r.runnerId === "b")!.waived).toBe(true);
    expect(report.complete).toBe(true);
    expect(report.passed).toBe(true);
  });

  it("site.skip removes runners from the default selection, on the record and without failing the run", async () => {
    const a = vi.fn(cleanObserve);
    const b = vi.fn(cleanObserve);
    fakeRunners = [fake("a", a), fake("b", b)];
    const report = await audit({ site: baseSite({ skip: ["b"] }) });
    expect(a).toHaveBeenCalled();
    expect(b).not.toHaveBeenCalled();
    expect(report.notAudited).toContainEqual(
      expect.objectContaining({ runnerId: "b", waived: true }),
    );
    expect(report.passed).toBe(true);
  });
});

describe("AuditReport shape — the contract CI consumes", () => {
  it("wires totals/passed/failOn from the actual results, not independently", async () => {
    fakeRunners = [
      fake("clean", cleanObserve),
      fake("bad", async () => ({
        kind: "observed",
        findings: [{ id: "leak", title: "leak", severity: "critical" as const }],
        coverage: LOOKED,
      })),
    ];
    const report = await audit({ site: baseSite({ failOn: "high" }) });
    expect(report.totals).toEqual({ critical: 1, high: 0, medium: 0, low: 0, info: 0 });
    expect(report.failOn).toBe("high");
    expect(report.passed).toBe(false);
    expect(report.complete).toBe(true); // both ran — the failure is findings, not coverage
    expect(report.site).toBe("site");
    expect(report.results).toHaveLength(2);
  });
});
