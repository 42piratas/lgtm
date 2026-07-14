import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { hasDocker, dockerRun } from "../util/docker.js";

// Static analysis via Semgrep (container) using curated security rulesets.
// White-box: needs the repo checkout. Ruleset fetch needs network.

const IMAGE = "semgrep/semgrep:latest";
const CONFIGS = ["p/security-audit", "p/secrets", "p/owasp-top-ten", "p/javascript", "p/typescript"];

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
}

export const sastRunner: Runner = {
  id: "sast",
  domain: "sast",
  title: "Static analysis (Semgrep)",
  requires: { repo: true, docker: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

    if (!(await hasDocker())) {
      return skip(this, start, "docker unavailable (semgrep image needs it)");
    }

    const configArgs = CONFIGS.flatMap((c) => ["--config", c]);
    const r = await dockerRun({
      image: IMAGE,
      args: ["semgrep", "scan", ...configArgs, "--json", "--quiet", "--timeout", "0", "/src"],
      mounts: { "/src": repo },
      timeoutMs: 480_000,
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
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `semgrep produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
        findings,
        durationMs: Date.now() - start,
      };
    }
    let out: SemgrepOutput;
    try {
      out = JSON.parse(r.stdout.slice(s));
    } catch (err) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `semgrep produced unparseable JSON: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
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

    if (findings.length === 0) {
      findings.push({
        id: "sast-ok",
        title: "No Semgrep findings across security rulesets",
        severity: "info",
      });
    }

    return {
      runnerId: this.id,
      domain: this.domain,
      status: "ok",
      note: out.errors?.length ? `${out.errors.length} scan error(s)` : undefined,
      findings,
      durationMs: Date.now() - start,
    };
  },
};

function skip(r: Runner, start: number, note: string): RunnerResult {
  return {
    runnerId: r.id,
    domain: r.domain,
    status: "skipped",
    note,
    findings: [],
    durationMs: Date.now() - start,
  };
}
