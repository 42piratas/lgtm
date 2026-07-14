import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun } from "../util/docker.js";

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

/**
 * gitleaks says what it did on stderr and nowhere else:
 *
 *   INF 14 commits scanned.
 *   INF scanned ~554058 bytes (554.06 KB) in 338ms
 *   INF no leaks found
 *
 * Point it at a directory that is not a git repo and it prints "0 commits
 * scanned", "no leaks found", and exits 0 — a clean bill of health for a scan
 * that read nothing. The commit and byte counts are the only way to tell that
 * apart from a genuinely clean repo, so they are the coverage.
 */
function scanLog(stderr: string): { commits: number; bytes: number } {
  const commits = stderr.match(/(\d+) commits scanned/);
  const bytes = stderr.match(/scanned ~(\d+) bytes/);
  return {
    commits: commits ? Number(commits[1]) : 0,
    bytes: bytes ? Number(bytes[1]) : 0,
  };
}

export const secretsRunner: Runner = {
  id: "secrets",
  domain: "secrets",
  title: "Leaked secrets (gitleaks)",
  requires: { repo: true, docker: true },

  sufficient(cov: Coverage): string | null {
    if (Number(cov.data.commits ?? 0) === 0) {
      return "gitleaks scanned 0 commits — the path is not a git repository, or has no history";
    }
    if (Number(cov.data.bytes ?? 0) === 0) {
      return "gitleaks read 0 bytes — nothing was actually examined";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

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

    const { commits, bytes } = scanLog(r.stderr);

    // A clean gitleaks run writes NOTHING to the report path — not `[]`, not
    // `{}`, zero bytes. An empty stdout is therefore not evidence of a crash
    // and must not be treated as one; doing so failed every clean repo. What
    // separates a clean scan from a dead one is the scan log, and that is what
    // `sufficient()` reads. All we need to catch here is output we cannot
    // interpret at all.
    let leaks: Leak[] = [];
    const s = r.stdout.indexOf("[");
    if (s >= 0) {
      try {
        const parsed = JSON.parse(r.stdout.slice(s));
        if (!Array.isArray(parsed)) throw new Error("report was not a JSON array");
        leaks = parsed;
      } catch (err) {
        return {
          kind: "failed",
          note: `gitleaks produced unparseable output: ${(err as Error).message}`,
        };
      }
    } else if (r.stdout.trim().length > 0) {
      return {
        kind: "failed",
        note: `gitleaks produced unrecognised output (exit ${r.code}): ${r.stdout.slice(0, 300)}`,
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

    return {
      kind: "observed",
      findings,
      coverage: {
        trail: [
          `scanned ${commits} commit${commits === 1 ? "" : "s"} of history`,
          `read ${bytes} bytes of content`,
        ],
        data: { commits, bytes },
        provenance: "gitleaks scan log (stderr)",
      },
      meta: { leakCount: findings.length, commits, bytes },
    };
  },
};
