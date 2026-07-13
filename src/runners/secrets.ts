import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { hasDocker, dockerRun } from "../util/docker.js";

// Leaked-credential scan via gitleaks (container), over the repo's git history
// and working tree. White-box: needs the repo checkout.

const IMAGE = "ghcr.io/gitleaks/gitleaks:latest";

interface Leak {
  Description?: string;
  File?: string;
  StartLine?: number;
  RuleID?: string;
  Commit?: string;
  Secret?: string;
}

export const secretsRunner: Runner = {
  id: "secrets",
  domain: "secrets",
  title: "Leaked secrets (gitleaks)",
  requires: { repo: true, docker: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

    if (!(await hasDocker())) {
      return skip(this, start, "docker unavailable (gitleaks image needs it)");
    }

    // Report to stdout as JSON; exit-code 0 so we read output ourselves.
    const r = await dockerRun({
      image: IMAGE,
      args: [
        "detect",
        "--source",
        "/repo",
        "--report-format",
        "json",
        "--report-path",
        "/dev/stdout",
        "--redact",
        "--no-banner",
        "--exit-code",
        "0",
      ],
      mounts: { "/repo": repo },
      timeoutMs: 300_000,
    });

    // A clean gitleaks JSON report is still a `[]` on stdout — if there's no
    // `[` at all, or what follows it isn't a JSON array, the tool didn't
    // actually report anything (crash, killed, wrong flags). That's
    // "unknown", not "no secrets": defaulting `leaks` to `[]` in that case
    // (as this code used to) makes a dead scan indistinguishable from a
    // clean one, and the `!Array.isArray` check below it never caught that
    // because the default was already an array.
    const s = r.stdout.indexOf("[");
    if (s < 0) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `gitleaks produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
        findings,
        durationMs: Date.now() - start,
      };
    }
    let leaks: Leak[];
    try {
      const parsed = JSON.parse(r.stdout.slice(s));
      if (!Array.isArray(parsed)) throw new Error("gitleaks report was not a JSON array");
      leaks = parsed;
    } catch (err) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `gitleaks produced unparseable output: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
      };
    }

    // Collapse duplicate rule+file pairs (a secret repeated across history).
    const seen = new Set<string>();
    for (const leak of leaks) {
      const key = `${leak.RuleID}:${leak.File}:${leak.StartLine}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `secret-${leak.RuleID ?? "generic"}`,
        title: `${leak.Description ?? "Potential secret"} in ${leak.File}:${leak.StartLine ?? "?"}`,
        severity: "critical",
        standard: "OWASP ASVS 2.10 / gitleaks",
        location: `${leak.File}:${leak.StartLine ?? ""}${leak.Commit ? ` @${leak.Commit.slice(0, 8)}` : ""}`,
        remediation:
          "Rotate the exposed credential immediately, then purge it from git history (git filter-repo / BFG).",
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: "secrets-ok",
        title: "No leaked secrets detected in tree or history",
        severity: "info",
      });
    }

    return {
      runnerId: this.id,
      domain: this.domain,
      status: "ok",
      findings,
      durationMs: Date.now() - start,
      meta: { leakCount: findings.filter((f) => f.severity !== "info").length },
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
