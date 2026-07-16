import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun } from "../util/docker.js";

// Static analysis via Semgrep (container) using curated security rulesets.
// White-box: needs the repo checkout. Ruleset fetch needs network.

const IMAGE = "semgrep/semgrep:latest";
const CONFIGS = ["p/security-audit", "p/secrets", "p/owasp-top-ten", "p/javascript", "p/typescript"];

// Scan scope. A PR gate answers "does THIS change add a finding" — so when the
// caller sets LGTM_SAST_BASELINE_REF (the gate sets it to the PR's base SHA),
// semgrep runs diff-aware (`--baseline-commit`): it scans HEAD and the baseline
// and reports only findings NEW since that ref, so pre-existing findings in
// untouched files never fail a PR. Unset (e.g. the scheduled sweep) → full-tree
// scan, which owns the backlog. Diff mode needs git inside the container to
// reach the baseline, so the checkout is mounted read-write and git safe.directory
// is pre-set to dodge the "dubious ownership" refusal on the foreign-uid mount.
const BASELINE_REF = process.env.LGTM_SAST_BASELINE_REF?.trim() || "";

const SEVERITY_MAP: Record<string, Finding["severity"]> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
};

interface SemgrepOutput {
  results?: Array<{
    check_id?: string;
    path?: string;
    start?: { line?: number };
    extra?: { severity?: string; message?: string; metadata?: { cwe?: string[] } };
  }>;
  errors?: Array<{ message?: string }>;
  /** Semgrep's own record of what it read. `scanned` is the file list. */
  paths?: { scanned?: string[] };
}

export const sastRunner: Runner = {
  id: "sast",
  domain: "sast",
  title: "Static analysis (Semgrep)",
  requires: { repo: true, docker: true },

  /**
   * Semgrep reports `results: []` whether it found nothing wrong or read
   * nothing at all — point it at a repo whose languages none of the rulesets
   * cover and it scans zero files, exits 0, and looks spotless. `paths.scanned`
   * is the file list it actually opened, and an empty one is not a pass.
   */
  sufficient(cov: Coverage): string | null {
    if (Number(cov.data.filesScanned ?? 0) === 0) {
      return "semgrep scanned 0 files — no source the rulesets understand was found";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

    const configArgs = CONFIGS.flatMap((c) => ["--config", c]);
    const r = await dockerRun({
      image: IMAGE,
      // Bound semgrep's resource use so it degrades gracefully instead of
      // OOM-dying with no output — the failure mode that ran ~24 min then exited
      // by signal on a large TS repo (alfred-app), leaving the gate un-passable.
      //   --max-memory: per-rule×file RAM cap (MiB); an oversized target is
      //     SKIPPED (surfaced as a scan error) rather than blowing up the process.
      //   --jobs 1: this cap is PER WORKER, and semgrep otherwise forks
      //     ~cores workers — on a multi-core runner N × the cap can still exceed
      //     host RAM. Pinning one worker makes the ceiling deterministic
      //     (~4 GB + base) and safe on the 7 GB GitHub-hosted runner regardless
      //     of core count; a gate must be reliable before fast.
      //   --timeout / --timeout-threshold: bound pathological rule×file combos
      //     the previous `--timeout 0` (unbounded) let hang indefinitely.
      args: [
        "semgrep",
        "scan",
        ...configArgs,
        "--json",
        "--quiet",
        "--jobs",
        "1",
        "--timeout",
        "120",
        "--timeout-threshold",
        "3",
        "--max-memory",
        "4000",
        // Diff-aware when the caller passes a baseline: only findings introduced
        // since that ref are reported (the gate sets it to the PR base SHA).
        ...(BASELINE_REF ? ["--baseline-commit", BASELINE_REF] : []),
        "/src",
      ],
      // Full scan is read-only; diff mode needs git to reach the baseline commit,
      // so mount RW and pre-declare /src a safe.directory (foreign-uid mount).
      ...(BASELINE_REF
        ? {
            mountsRW: { "/src": repo },
            extra: [
              "-e",
              "GIT_CONFIG_COUNT=1",
              "-e",
              "GIT_CONFIG_KEY_0=safe.directory",
              "-e",
              "GIT_CONFIG_VALUE_0=/src",
            ],
          }
        : { mounts: { "/src": repo } }),
      timeoutMs: 900_000,
    });

    // A clean semgrep --json run always emits at least `{"results":[]}`. If
    // semgrep dies before writing anything, stdout has no `{` at all — the
    // old code's `if (s >= 0)` guard meant that case skipped the parse
    // entirely without throwing, `out` stayed `{}`, and a crashed scan
    // reported "No Semgrep findings": a gate going green on a repo that was
    // never scanned. Both "no `{` at all" and "what follows it doesn't
    // parse" are the same failure and must both error.
    const s = r.stdout.indexOf("{");
    if (s < 0) {
      return {
        kind: "failed",
        note: `semgrep produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
      };
    }
    let out: SemgrepOutput;
    try {
      out = JSON.parse(r.stdout.slice(s));
    } catch (err) {
      return {
        kind: "failed",
        note: `semgrep produced unparseable JSON: ${(err as Error).message}`,
      };
    }

    // Collapse repeated rule hits to the top 100 by severity to keep signal.
    const seen = new Set<string>();
    for (const res of out.results ?? []) {
      const rel = (res.path ?? "").replace(/^\/src\/?/, "");
      const key = `${res.check_id}:${rel}:${res.start?.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const sev = SEVERITY_MAP[res.extra?.severity ?? "INFO"] ?? "low";
      const cwe = res.extra?.metadata?.cwe?.[0];
      findings.push({
        id: `sast-${res.check_id ?? "rule"}`,
        title: `${(res.extra?.message ?? res.check_id ?? "").slice(0, 140)}`,
        severity: sev,
        standard: cwe ?? "Semgrep",
        location: `${rel}:${res.start?.line ?? ""}`,
        remediation: `Rule ${res.check_id}. Review and remediate per the rule guidance.`,
      });
    }

    const scanned = out.paths?.scanned ?? [];

    return {
      kind: "observed",
      note: out.errors?.length ? `${out.errors.length} scan error(s)` : undefined,
      findings,
      coverage: {
        trail: [
          `scanned ${scanned.length} file${scanned.length === 1 ? "" : "s"} against ${CONFIGS.length} rulesets (${CONFIGS.join(", ")})`,
        ],
        data: { filesScanned: scanned.length, rulesets: CONFIGS.length },
        provenance: "semgrep --json paths.scanned",
      },
      meta: { filesScanned: scanned.length },
    };
  },
};
