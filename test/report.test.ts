import { describe, it, expect, afterEach, vi } from "vitest";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeReports } from "../src/report.js";
import type { AuditReport } from "../src/types.js";

// The JSON report is what CI (42L-949) actually reads to gate a build.
// totals / passed / failOn must round-trip exactly as the orchestrator
// computed them — this is the contract, and it must stay stable.

let cwdSpy: ReturnType<typeof vi.spyOn> | undefined;
let workDir: string;

afterEach(() => {
  cwdSpy?.mockRestore();
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

function sampleReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    site: "mysite",
    baseUrl: "https://example.com",
    stamp: "250101-1200",
    startedAt: "2025-01-01T12:00:00.000Z",
    finishedAt: "2025-01-01T12:01:00.000Z",
    isLocalhost: false,
    allowActive: false,
    results: [
      {
        runnerId: "headers",
        domain: "security",
        status: "ok",
        findings: [{ id: "csp", title: "no CSP", severity: "high" }],
        durationMs: 42,
      },
      {
        runnerId: "deps",
        domain: "deps",
        status: "skipped",
        note: "no repoPath configured (white-box runner)",
        findings: [],
        durationMs: 0,
      },
    ],
    totals: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    passed: false,
    complete: false,
    notAudited: [
      {
        runnerId: "deps",
        reason: "no repoPath configured — this domain was never scanned",
        waived: false,
      },
    ],
    failOn: "high",
    ...overrides,
  };
}

describe("writeReports — JSON contract", () => {
  it("writes a JSON file whose shape matches the AuditReport exactly", () => {
    workDir = mkdtempSync(join(tmpdir(), "lgtm-report-test-"));
    cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workDir);

    const report = sampleReport();
    const { json, html } = writeReports(report);

    expect(json).toBe(join(workDir, "reports", "mysite", "mysite-250101-1200.json"));
    const parsed = JSON.parse(readFileSync(json, "utf8"));
    expect(parsed.totals).toEqual({ critical: 0, high: 1, medium: 0, low: 0, info: 0 });
    expect(parsed.passed).toBe(false);
    expect(parsed.failOn).toBe("high");
    expect(parsed.site).toBe("mysite");
    expect(parsed.results).toHaveLength(2);

    // HTML is a rendering concern, not the CI contract — just confirm it was
    // produced and isn't empty, without asserting on markup.
    const htmlContents = readFileSync(html, "utf8");
    expect(htmlContents.length).toBeGreaterThan(0);
    expect(htmlContents).toContain("FAIL");
  });

  it("reflects a passing run's shape too — clean means no findings AND full coverage", () => {
    workDir = mkdtempSync(join(tmpdir(), "lgtm-report-test-"));
    cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workDir);

    const report = sampleReport({
      results: [
        {
          runnerId: "headers",
          domain: "security",
          status: "ok",
          findings: [],
          durationMs: 10,
          coverage: {
            trail: ["GET https://example.com → 200"],
            data: { responded: true, checksEvaluated: 7 },
            provenance: "response headers of the base URL",
          },
        },
      ],
      totals: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      passed: true,
      complete: true,
      notAudited: [],
    });
    const { json } = writeReports(report);
    const parsed = JSON.parse(readFileSync(json, "utf8"));
    expect(parsed.passed).toBe(true);
    expect(parsed.complete).toBe(true);
    expect(parsed.notAudited).toEqual([]);
  });

  // 42L-1003: an errored runner can still carry real findings — authz reports
  // the genuinely-open route it DID find alongside the routes it couldn't check.
  // The section body rendered only the "refused to score" banner and dropped the
  // findings table, while the severity tiles at the top went on counting them:
  // the KPI said "1 high", the section said nothing. A finding the reader cannot
  // see does not exist to them.
  it("renders the findings an errored runner DID observe, not just the refusal banner", () => {
    workDir = mkdtempSync(join(tmpdir(), "lgtm-report-test-"));
    cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workDir);

    const report = sampleReport({
      results: [
        {
          runnerId: "authz",
          domain: "authz",
          status: "error",
          note: "could not check 2 of 3 routes",
          findings: [
            {
              id: "authz-open-route",
              title: "/admin is reachable without authentication",
              severity: "critical",
              location: "https://example.com/admin",
            },
          ],
          durationMs: 10,
        },
      ],
      totals: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      passed: false,
    });

    const { html } = writeReports(report);
    const contents = readFileSync(html, "utf8");

    expect(contents).toContain("Refused to score");
    // The finding the KPI tile is already counting must be visible in the body.
    expect(contents).toContain("/admin is reachable without authentication");
    expect(contents).toContain("https://example.com/admin");
  });
});

describe("report.ts — countAtOrAbove (the number the operator actually reads)", () => {
  // countAtOrAbove() is private, but it's the figure in the FAIL verdict line
  // ("FAIL — N findings at or above high"). An off-by-one here doesn't corrupt
  // the gate, but it hands the operator a wrong count in the one place they
  // look. Asserted through the rendered HTML, since that's its only surface.
  function verdictCount(totals: Record<string, number>, failOn: AuditReport["failOn"]): number {
    workDir = mkdtempSync(join(tmpdir(), "lgtm-report-count-"));
    cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workDir);
    const { html } = writeReports(
      sampleReport({
        totals: totals as AuditReport["totals"],
        failOn,
        passed: false,
        // Full coverage, so the ONLY thing the verdict line has to report is
        // the finding count — otherwise the unaudited-domain clause leads and
        // this test would be reading the wrong number.
        complete: true,
        notAudited: [],
        results: [],
      }),
    );
    const rendered = readFileSync(html, "utf8");
    const m = rendered.match(/(\d+) findings? at or above/);
    expect(m).not.toBeNull();
    return Number(m![1]);
  }

  it("counts only findings at or above the threshold — not everything below it", () => {
    // failOn high → critical + high count (2 + 3); medium/low/info must not.
    const n = verdictCount(
      { critical: 2, high: 3, medium: 10, low: 20, info: 40 },
      "high",
    );
    expect(n).toBe(5);
  });

  it("counts critical only when the threshold is critical", () => {
    const n = verdictCount({ critical: 2, high: 3, medium: 10, low: 20, info: 40 }, "critical");
    expect(n).toBe(2);
  });

  it("includes the threshold's own severity band (medium threshold counts mediums)", () => {
    const n = verdictCount({ critical: 1, high: 1, medium: 1, low: 99, info: 99 }, "medium");
    expect(n).toBe(3);
  });

  it("counts every real severity at a low threshold, still excluding info", () => {
    const n = verdictCount({ critical: 1, high: 2, medium: 3, low: 4, info: 99 }, "low");
    expect(n).toBe(10);
  });
});
