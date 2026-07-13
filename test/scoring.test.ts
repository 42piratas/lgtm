import { describe, it, expect } from "vitest";
import {
  severityRank,
  atLeastAsSevere,
  realFindings,
  tallySeverities,
  computePass,
  gradeFor,
} from "../src/scoring.js";
import type { Finding, RunnerResult, Severity } from "../src/types.js";

// This module is the CI gate: computePass decides the exit code that a
// downstream pipeline (42L-949) will act on. If it's wrong, CI lies —
// either failing a clean site or, worse, passing a broken one. Every
// severity boundary and every short-circuit (info, skipped, error) is
// tested explicitly rather than through a handful of "looks about right"
// cases.

function finding(severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return { id: "f", title: "finding", severity, ...overrides };
}

function result(
  findings: Finding[],
  overrides: Partial<RunnerResult> = {},
): RunnerResult {
  return {
    runnerId: "r",
    domain: "security",
    status: "ok",
    findings,
    durationMs: 1,
    ...overrides,
  };
}

describe("severityRank / atLeastAsSevere", () => {
  it("orders severities from most to least severe", () => {
    expect(severityRank("critical")).toBe(0);
    expect(severityRank("high")).toBe(1);
    expect(severityRank("medium")).toBe(2);
    expect(severityRank("low")).toBe(3);
    expect(severityRank("info")).toBe(4);
  });

  it("treats equal severities as at-least-as-severe", () => {
    (["critical", "high", "medium", "low", "info"] as Severity[]).forEach((s) => {
      expect(atLeastAsSevere(s, s)).toBe(true);
    });
  });

  it("is true when the left side is strictly more severe", () => {
    expect(atLeastAsSevere("critical", "high")).toBe(true);
    expect(atLeastAsSevere("high", "medium")).toBe(true);
    expect(atLeastAsSevere("critical", "info")).toBe(true);
  });

  it("is false when the left side is strictly less severe", () => {
    expect(atLeastAsSevere("low", "high")).toBe(false);
    expect(atLeastAsSevere("info", "critical")).toBe(false);
    expect(atLeastAsSevere("medium", "critical")).toBe(false);
  });
});

describe("realFindings", () => {
  it("drops info pass-notes and keeps everything else", () => {
    const fs = [finding("info"), finding("low"), finding("critical"), finding("info")];
    expect(realFindings(fs).map((f) => f.severity)).toEqual(["low", "critical"]);
  });

  it("returns an empty array when every finding is info", () => {
    expect(realFindings([finding("info"), finding("info")])).toEqual([]);
  });
});

describe("tallySeverities", () => {
  it("zero-fills every severity bucket, even with no results", () => {
    expect(tallySeverities([])).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });

  it("counts findings across multiple runner results", () => {
    const results = [
      result([finding("critical"), finding("high"), finding("info")]),
      result([finding("high"), finding("low")]),
      result([]), // e.g. a skipped runner contributes nothing
    ];
    expect(tallySeverities(results)).toEqual({
      critical: 1,
      high: 2,
      medium: 0,
      low: 1,
      info: 1,
    });
  });
});

describe("computePass — the CI gate", () => {
  it("passes on a run with zero findings", () => {
    expect(computePass([result([])], "high")).toBe(true);
  });

  it("passes on a run with only info findings, regardless of threshold", () => {
    const results = [result([finding("info"), finding("info")])];
    (["critical", "high", "medium", "low", "info"] as Severity[]).forEach((failOn) => {
      expect(computePass(results, failOn)).toBe(true);
    });
  });

  it("fails when a finding sits exactly at the failOn threshold", () => {
    // Every severity, checked against itself as the threshold: this is the
    // boundary most likely to be off-by-one in a `<` vs `<=` comparison.
    (["critical", "high", "medium", "low"] as Severity[]).forEach((sev) => {
      expect(computePass([result([finding(sev)])], sev)).toBe(false);
    });
  });

  it("passes when the worst finding is one level below the threshold", () => {
    expect(computePass([result([finding("medium")])], "high")).toBe(true);
    expect(computePass([result([finding("low")])], "medium")).toBe(true);
    expect(computePass([result([finding("info")])], "low")).toBe(true);
  });

  it("fails when the worst finding is more severe than the threshold", () => {
    expect(computePass([result([finding("critical")])], "high")).toBe(false);
    expect(computePass([result([finding("high")])], "medium")).toBe(false);
  });

  it("never fails on an info-severity threshold unless something is at or above low", () => {
    // failOn: "info" is a real (if extreme) config value — only info findings
    // exist below it, and those are explicitly exempted, so failOn: "info"
    // fails on ANY real finding but passes a genuinely clean/info-only run.
    expect(computePass([result([finding("low")])], "info")).toBe(false);
    expect(computePass([result([finding("info")])], "info")).toBe(true);
  });

  it("fails if any one of several runners has a qualifying finding", () => {
    const results = [
      result([finding("info")], { runnerId: "headers" }),
      result([], { runnerId: "cookies" }),
      result([finding("critical")], { runnerId: "secrets" }),
    ];
    expect(computePass(results, "high")).toBe(false);
  });

  it("is unaffected by skipped or errored runners with empty findings", () => {
    const results = [
      result([], { status: "skipped", note: "no repoPath configured" }),
      result([], { status: "error", note: "fetch failed" }),
    ];
    expect(computePass(results, "low")).toBe(true);
  });
});

describe("gradeFor", () => {
  it("grades a skipped runner as em-dash, not a letter", () => {
    expect(gradeFor(result([], { status: "skipped", note: "no repoPath" }))).toBe("—");
  });

  it("grades an errored runner as '?'", () => {
    expect(gradeFor(result([], { status: "error", note: "boom" }))).toBe("?");
  });

  it("grades a clean run (no findings) as A", () => {
    expect(gradeFor(result([]))).toBe("A");
  });

  it("grades info-only findings as A — info is a pass-note, not an issue", () => {
    expect(gradeFor(result([finding("info"), finding("info")]))).toBe("A");
  });

  it("maps each real severity to its letter", () => {
    expect(gradeFor(result([finding("low")]))).toBe("B");
    expect(gradeFor(result([finding("medium")]))).toBe("C");
    expect(gradeFor(result([finding("high")]))).toBe("D");
    expect(gradeFor(result([finding("critical")]))).toBe("F");
  });

  it("grades by the single worst finding, not the first or last", () => {
    const r = result([finding("low"), finding("critical"), finding("medium")]);
    expect(gradeFor(r)).toBe("F");
  });
});
