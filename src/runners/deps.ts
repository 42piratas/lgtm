import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun } from "../util/docker.js";

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

/**
 * osv-scanner's JSON lists only the sources that HAVE vulnerabilities — a
 * fully clean repo and a repo where the walk found no lockfiles at all both
 * come back as `{"results":[]}`. The proof of work is in the walk log it
 * writes to stderr, one line per manifest it actually parsed:
 *
 *   Scanned /src/package-lock.json file and found 304 packages
 *
 * That line is the only place the tool says what it looked at, so that is
 * where the coverage has to come from.
 */
function walkedSources(stderr: string): Array<{ path: string; packages: number }> {
  const out: Array<{ path: string; packages: number }> = [];
  // "…and found 1 package" — osv-scanner pluralises, so an insistence on the
  // plural would miss every single-dependency manifest, and this runner would
  // then refuse a repo it had genuinely scanned.
  const re = /Scanned (\S+) file and found (\d+) packages?/g;
  for (const m of stderr.matchAll(re)) {
    out.push({ path: m[1]!, packages: Number(m[2]) });
  }
  return out;
}

export const depsRunner: Runner = {
  id: "deps",
  domain: "deps",
  title: "Dependency CVEs (osv-scanner)",
  requires: { repo: true, docker: true },

  /**
   * Zero lockfiles walked means the whole dependency tree went unexamined —
   * the single most common way this runner lies, because a gitignored
   * lockfile silently removes an entire ecosystem from the scan and the tool
   * still exits reporting nothing.
   */
  sufficient(cov: Coverage): string | null {
    if (Number(cov.data.sources ?? 0) === 0) {
      return "no lockfiles or manifests were walked — the dependency tree was never audited";
    }
    // Deliberately NOT checking the package count. A manifest that genuinely
    // resolves to zero dependencies (a fresh scaffold) has been audited — there
    // was simply nothing in it. Refusing that would fail a healthy repo, which
    // is the same disservice as passing an unscanned one.
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

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

    const sources = walkedSources(r.stderr);

    const emptyCoverage: Coverage = {
      trail: ["walked no lockfile or manifest"],
      data: { sources: 0, packages: 0 },
      provenance: "osv-scanner walk log (stderr)",
    };

    // A repo with nothing to scan is osv-scanner's exit 128, "No package sources
    // found". That is not a broken tool — the tool worked perfectly and found
    // nothing to look at, which is a COVERAGE fact, not an error. Reporting it
    // as "osv-scanner error (exit 128)" sent the operator hunting a container
    // problem when the real answer is that a lockfile is gitignored and an
    // entire ecosystem is going unaudited. Hand it to sufficient(), which says
    // so in as many words.
    if (/no package sources found/i.test(r.stderr)) {
      return { kind: "observed", findings, coverage: emptyCoverage };
    }

    // osv-scanner exits 1 when vulns are found, 0 when clean, >1 on real error.
    if (r.code > 1 && !r.stdout.trim().startsWith("{")) {
      return {
        kind: "failed",
        note: `osv-scanner error (exit ${r.code}): ${r.stderr.slice(0, 300)}`,
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
        kind: "failed",
        note: `osv-scanner produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
      };
    }
    let out: OsvOutput;
    try {
      out = JSON.parse(r.stdout.slice(s));
    } catch (err) {
      return {
        kind: "failed",
        note: `osv-scanner produced unparseable JSON: ${(err as Error).message}`,
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

    const packages = sources.reduce((n, s2) => n + s2.packages, 0);

    return {
      kind: "observed",
      findings,
      coverage: {
        trail: sources.map(
          (s2) => `walked ${s2.path.replace(/^\/src\/?/, "")} — ${s2.packages} packages`,
        ),
        data: { sources: sources.length, packages },
        provenance: "osv-scanner walk log (stderr)",
      },
      meta: { sources: sources.map((s2) => s2.path), packages },
    };
  },
};
