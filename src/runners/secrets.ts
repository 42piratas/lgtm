import { mkdirSync, readFileSync, existsSync, rmSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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

// Baseline config shipped beside this file. `useDefault = true` keeps the full
// upstream ruleset and only adds an allowlist for hash-shaped literals (content
// hashes, SRI integrity) that the generic-api-key rule otherwise reports as
// critical secrets. Resolved from the module URL, not cwd, so it works whatever
// directory the CLI is invoked from.
const BASELINE_CONFIG = fileURLToPath(
  new URL("./gitleaks-baseline.toml", import.meta.url),
);

// gitleaks scans the FULL git history. On large repos (thousands of commits,
// 100 MB+ packs) the old 5-min cap killed the container before it wrote a
// report, which fail-closes the gate with an opaque "wrote no report (exit -1)"
// on EVERY run — a false fail, not a detected secret. Mirror the sast runner's
// large-repo hardening (PR #17: 15-min semgrep cap): default to 15 min, and let
// pathological histories raise it via LGTM_SECRETS_TIMEOUT_MS without a rebuild.
const DEFAULT_TIMEOUT_MS = 900_000;
const TIMEOUT_MS =
  Number(process.env.LGTM_SECRETS_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;

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

    // The report goes to a FILE in a bind-mounted work dir, never to
    // `--report-path /dev/stdout`.
    //
    // gitleaks accepts /dev/stdout without complaint and then writes nothing to
    // it — verified against the pinned image (v8.30.1): a repo with two planted
    // AWS keys logs "leaks found: 2" on stderr and delivers 0 bytes on stdout,
    // while the same scan pointed at a real path writes a 1223-byte JSON array.
    // This runner read stdout. It has therefore never reported a single leaked
    // secret: every repo, clean or compromised, came back with nothing to say.
    // The old code was accidentally shielded from shipping that as a pass (it
    // read empty stdout as a crash and errored); reading it as "clean" — which
    // is what an evidence contract SHOULD do with a scan that examined 14
    // commits and found nothing — would have turned a loud wrong answer into a
    // silent one. The bug is the flag, so fix the flag.
    const work = join(process.cwd(), "reports", ".work", `secrets-${ctx.run.stamp}`);
    mkdirSync(work, { recursive: true });
    chmodSync(work, 0o777); // the image runs as a non-root uid
    const reportPath = join(work, "gitleaks.json");

    try {
      const r = await dockerRun({
        image: IMAGE,
        args: [
          "detect",
          "--source",
          "/repo",
          "--config",
          "/config/gitleaks.toml",
          "--report-format",
          "json",
          "--report-path",
          "/out/gitleaks.json",
          "--redact",
          "--no-banner",
          "--exit-code",
          "0", // findings are not a failure — we read the report ourselves
        ],
        mounts: { "/repo": repo, "/config/gitleaks.toml": BASELINE_CONFIG },
        mountsRW: { "/out": work },
        timeoutMs: TIMEOUT_MS,
      });

      const { commits, bytes } = scanLog(r.stderr);

      // No report file at all means gitleaks never got as far as writing one:
      // a bad flag, a crash, a killed container. That is unknown, not clean.
      if (!existsSync(reportPath)) {
        // Distinguish the large-repo timeout (the common false-fail) from a real
        // crash so the fix is actionable, not an opaque "exit -1".
        if (r.timedOut) {
          return {
            kind: "failed",
            note: `gitleaks timed out after ${Math.round(TIMEOUT_MS / 1000)}s scanning full history (${commits} commits, ${bytes} bytes read before the kill) — raise LGTM_SECRETS_TIMEOUT_MS for very large repos.`,
          };
        }
        return {
          kind: "failed",
          note: `gitleaks wrote no report (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
        };
      }

      const raw = readFileSync(reportPath, "utf8").trim();
      // A clean repo yields an empty file — not `[]`. That is a real result, and
      // `sufficient()` decides whether the scan behind it was real, using the
      // commit and byte counts.
      let leaks: Leak[] = [];
      if (raw.length > 0) {
        try {
          const parsed = JSON.parse(raw);
          if (!Array.isArray(parsed)) throw new Error("report was not a JSON array");
          leaks = parsed;
        } catch (err) {
          return {
            kind: "failed",
            note: `gitleaks produced unparseable output: ${(err as Error).message}`,
          };
        }
      }
      return collect(leaks, commits, bytes, findings);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  },
};

function collect(
  leaks: Leak[],
  commits: number,
  bytes: number,
  findings: Finding[],
): RunnerOutcome {
  // Collapse duplicate rule+file pairs (a secret repeated across history).
  {
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
  }
}
