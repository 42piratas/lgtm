import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { hasDocker, dockerRun } from "../util/docker.js";

// Dependency CVEs via Google's osv-scanner (container). White-box: needs the
// repo checkout. Reports lockfile-resolved vulnerabilities across ecosystems.

const IMAGE = "ghcr.io/google/osv-scanner:latest";

const SEVERITY_MAP = (cvss?: number): Finding["severity"] => {
  if (cvss === undefined) return "medium";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
};

interface OsvOutput {
  results?: Array<{
    source?: { path?: string };
    packages?: Array<{
      package?: { name?: string; version?: string };
      vulnerabilities?: Array<{
        id?: string;
        summary?: string;
        severity?: Array<{ type?: string; score?: string }>;
        database_specific?: { severity?: string };
      }>;
    }>;
  }>;
}

function cvssFrom(v: { severity?: Array<{ score?: string }> }): number | undefined {
  const raw = v.severity?.[0]?.score;
  if (!raw) return undefined;
  // CVSS vector or numeric — extract a base score if present.
  const m = raw.match(/(\d+(\.\d+)?)/);
  return m ? Number(m[1]) : undefined;
}

export const depsRunner: Runner = {
  id: "deps",
  domain: "deps",
  title: "Dependency CVEs (osv-scanner)",
  requires: { repo: true, docker: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

    if (!(await hasDocker())) {
      return skip(this, start, "docker unavailable (osv-scanner image needs it)");
    }

    // osv-scanner respects the repo's .gitignore by default. That's correct
    // for build output, but real lockfiles are routinely gitignored too —
    // e.g. a Jekyll repo's Gemfile.lock (42piratas.com) — and get silently
    // excluded from the walk entirely: "No package sources found", the
    // *entire* ecosystem goes unaudited, and it looks like a tool error
    // rather than a coverage hole. --no-ignore restores them. The same
    // gitignore rule ordinarily hides node_modules, .git, and (in this
    // fleet's convention) .worktrees/ — --no-ignore would otherwise pull
    // those back in too (vendor noise, or duplicate scans of stale worktree
    // checkouts), so exclude them explicitly instead.
    const r = await dockerRun({
      image: IMAGE,
      args: [
        "scan",
        "source",
        "--recursive",
        "--no-ignore",
        "--experimental-exclude",
        "r:node_modules",
        "--experimental-exclude",
        "r:\\.git",
        "--experimental-exclude",
        "r:\\.worktrees",
        "--format",
        "json",
        "/src",
      ],
      mounts: { "/src": repo },
      timeoutMs: 300_000,
    });

    // osv-scanner exits 1 when vulns are found, 0 when clean, >1 on real error.
    if (r.code > 1 && !r.stdout.trim().startsWith("{")) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `osv-scanner error (exit ${r.code}): ${r.stderr.slice(0, 300)}`,
        findings,
        durationMs: Date.now() - start,
      };
    }

    // A clean osv-scanner JSON run always emits at least `{"results":[]}` —
    // if stdout has no `{` at all, or what follows it doesn't parse, the
    // tool didn't produce real output (crash, OOM, truncated write). That is
    // "unknown", not "zero vulnerabilities": silently falling through to an
    // empty `out` here is exactly how a dead scanner reports a clean pass.
    const s = r.stdout.indexOf("{");
    if (s < 0) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `osv-scanner produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
        findings,
        durationMs: Date.now() - start,
      };
    }
    let out: OsvOutput;
    try {
      out = JSON.parse(r.stdout.slice(s));
    } catch (err) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `osv-scanner produced unparseable JSON: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
      };
    }

    for (const result of out.results ?? []) {
      for (const pkg of result.packages ?? []) {
        for (const v of pkg.vulnerabilities ?? []) {
          const cvss = cvssFrom(v);
          findings.push({
            id: `dep-${v.id ?? "unknown"}`,
            title: `${pkg.package?.name}@${pkg.package?.version}: ${v.id} — ${(v.summary ?? "").slice(0, 120)}`,
            severity: SEVERITY_MAP(cvss),
            standard: "OSV / GHSA",
            location: result.source?.path,
            remediation: `Upgrade ${pkg.package?.name} to a non-vulnerable version.`,
            evidence: v.id ? `https://osv.dev/vulnerability/${v.id}` : undefined,
          });
        }
      }
    }

    if (findings.length === 0) {
      findings.push({
        id: "deps-ok",
        title: "No known dependency vulnerabilities",
        severity: "info",
      });
    }

    return {
      runnerId: this.id,
      domain: this.domain,
      status: "ok",
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
