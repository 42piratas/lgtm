import {
  SEVERITY_ORDER,
  type Severity,
  type Runner,
  type RunnerContext,
  type RunnerResult,
  type Finding,
} from "./types.js";

/**
 * Turn what a runner SAW into a verdict. This is the only place in lgtm that
 * decides a domain is clean, and it will only do so when the runner's own
 * sufficiency rule confirms the coverage backs that claim.
 *
 * A runner cannot reach this decision itself: `RunnerOutcome` has no status
 * field to set. That is deliberate — the old contract let every runner assert
 * `status: "ok"` next to an empty findings array, which is exactly how a
 * scanner that never looked reports a clean bill of health.
 *
 * It lives here, beside the scoring rules it feeds and away from the runner
 * registry, so a runner's own tests can exercise the real decision path
 * without importing every other runner in the fleet.
 */
export async function derive(
  runner: Runner,
  ctx: RunnerContext,
  start: number = Date.now(),
): Promise<RunnerResult> {
  const base = { runnerId: runner.id, domain: runner.domain };
  const outcome = await runner.observe(ctx);
  const durationMs = Date.now() - start;

  if (outcome.kind === "notApplicable" || outcome.kind === "unavailable") {
    return {
      ...base,
      status: "skipped",
      note: outcome.note,
      findings: [],
      durationMs,
      waived: outcome.kind === "notApplicable",
    };
  }
  if (outcome.kind === "failed") {
    return {
      ...base,
      status: "error",
      note: outcome.note,
      findings: [],
      durationMs,
      meta: outcome.meta,
    };
  }

  const why = runner.sufficient(outcome.coverage, ctx);
  return {
    ...base,
    status: why ? "error" : "ok",
    note: why ? `insufficient evidence — ${why}` : outcome.note,
    // Findings stay attached even when the evidence is too thin to conclude:
    // whatever the tool did see is still worth reading, and dropping it here
    // would make the report contradict its own severity counts.
    findings: outcome.findings,
    durationMs,
    meta: outcome.meta,
    coverage: outcome.coverage,
  };
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** True when `a` is at least as severe as `b` (critical is most severe). */
export function atLeastAsSevere(a: Severity, b: Severity): boolean {
  return severityRank(a) <= severityRank(b);
}

/**
 * Real problems only — plain `info` findings are pass-notes, not issues.
 * A `needsReview` finding is technically severity "info" (never a confirmed
 * failure) but must stay visible rather than being swept in with pass-notes.
 */
export function realFindings(f: Finding[]): Finding[] {
  return f.filter((x) => x.severity !== "info" || x.needsReview);
}

export function tallySeverities(results: RunnerResult[]): Record<Severity, number> {
  const totals: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const r of results) for (const f of r.findings) totals[f.severity]++;
  return totals;
}

/**
 * A run passes when no runner errored AND no finding is at or above the
 * site's failOn threshold.
 *
 * A runner in status "error" could not actually see the site (auth gate,
 * bad HTTP status, tool crash, misconfigured scan) — it has no findings to
 * evaluate, but "no findings" here means "unknown", not "clean". Letting an
 * errored runner pass silently is exactly how a scanner ends up reporting a
 * false all-clear: it must not be reportable as anything other than a
 * failure.
 */
export function computePass(
  results: RunnerResult[],
  failOn: Severity,
): boolean {
  for (const r of results) {
    if (r.status === "error") return false;
    for (const f of r.findings) {
      if (f.severity !== "info" && atLeastAsSevere(f.severity, failOn)) {
        return false;
      }
    }
  }
  return true;
}

/** Letter grade for a runner from its worst finding. */
export function gradeFor(result: RunnerResult): string {
  if (result.status === "skipped") return "—";
  if (result.status === "error") return "?";
  const worst = realFindings(result.findings).reduce<Severity | null>(
    (acc, f) =>
      acc === null || atLeastAsSevere(f.severity, acc) ? f.severity : acc,
    null,
  );
  if (worst === null) return "A";
  const map: Record<Severity, string> = {
    critical: "F",
    high: "D",
    medium: "C",
    low: "B",
    info: "A",
  };
  return map[worst];
}
