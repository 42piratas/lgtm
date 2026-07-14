import { exec, which, type ExecResult } from "./exec.js";
import { withRetry, isTransientFailure } from "./retry.js";

let dockerAvailable: boolean | null = null;

/** Cached check: is the Docker daemon reachable (not just the CLI installed)? */
export async function hasDocker(): Promise<boolean> {
  if (dockerAvailable !== null) return dockerAvailable;
  if (!(await which("docker"))) return (dockerAvailable = false);
  const r = await exec("docker", ["info", "--format", "{{.ServerVersion}}"], {
    timeoutMs: 15_000,
  });
  return (dockerAvailable = r.code === 0);
}

export interface DockerRunOpts {
  image: string;
  args: string[];
  /** Host dirs to bind-mount read-only, keyed by container path. */
  mounts?: Record<string, string>;
  /** Bind-mount writable, keyed by container path. */
  mountsRW?: Record<string, string>;
  /** Container working dir. */
  workdir?: string;
  timeoutMs?: number;
  /** Share host network (needed to reach a localhost target from inside). */
  hostNetwork?: boolean;
  /** Extra `docker run` flags before the image. */
  extra?: string[];
  /**
   * Whether THIS tool's result looks like a transient infrastructure failure
   * worth one more attempt. Must be supplied per-tool, because "nonzero exit"
   * means completely different things to different scanners: osv-scanner exits
   * 1 when it FINDS vulnerabilities, semgrep and ZAP likewise signal findings
   * through the exit code. A shared "nonzero + looks transient" rule therefore
   * cannot tell a broken run from a successful one.
   *
   * Defaults to `transientInfraFailure`, which is deliberately conservative:
   * stderr only, never stdout. Runners whose output is a FILE (tls, zap) pass a
   * predicate that also checks the file wasn't written — see their call sites.
   */
  retryOn?: (r: ExecResult) => boolean;
}

/**
 * The safe default: retry only when the container itself failed to run, not
 * when the tool inside it ran and had something to say.
 *
 * Two rules do all the work:
 *
 *   1. Classify on STDERR ONLY. stdout is the tool's data channel — a real CVE
 *      summary mentioning "net/http", or a ZAP alert reporting a genuine 500 it
 *      elicited (which is the entire point of an active scan), used to match the
 *      transient patterns and retry a SUCCESSFUL scan from scratch. For ZAP
 *      that is up to 20 wasted minutes to reach the same answer.
 *   2. Require a nonzero exit AND transient-looking stderr. A nonzero exit alone
 *      is normal ("I found problems"); transient-looking text alone is normal
 *      (it's in the findings).
 */
export const transientInfraFailure = (r: ExecResult): boolean =>
  r.timedOut ||
  // 137 = SIGKILL, overwhelmingly the OOM-killer on a busy CI runner. It often
  // arrives with EMPTY stderr, so no text pattern can catch it — it has to be
  // matched on the code. Textbook transient: same input, likely fine on a
  // quieter retry.
  r.code === 137 ||
  (r.code !== 0 && isTransientFailure(r.stderr));

/**
 * For runners whose real output is a file on the bind-mount rather than stdout
 * (tls, zap): if the report file exists, the tool ran and produced its answer —
 * whatever the exit code says — so there is nothing to retry.
 */
export const transientInfraFailureUnless = (
  producedOutput: () => boolean,
): ((r: ExecResult) => boolean) => {
  return (r) => !producedOutput() && transientInfraFailure(r);
};

/**
 * Run a one-shot container and capture output. `--rm`, no TTY, dropped caps.
 * Scanner images are the delivery mechanism for tools we don't install on the
 * host (semgrep, gitleaks, osv-scanner, testssl, ZAP).
 */
export async function dockerRun(opts: DockerRunOpts) {
  const {
    image,
    args,
    mounts = {},
    mountsRW = {},
    workdir,
    timeoutMs = 600_000,
    hostNetwork = false,
    extra = [],
    retryOn = transientInfraFailure,
  } = opts;

  const runArgs = ["run", "--rm", "--pull=missing"];
  if (hostNetwork) runArgs.push("--network=host");
  for (const [ctr, host] of Object.entries(mounts)) {
    runArgs.push("-v", `${host}:${ctr}:ro`);
  }
  for (const [ctr, host] of Object.entries(mountsRW)) {
    runArgs.push("-v", `${host}:${ctr}`);
  }
  if (workdir) runArgs.push("-w", workdir);
  runArgs.push(...extra, image, ...args);

  // Bounded retry for transient container failures (image-pull timeout,
  // registry throttle, OOM-killed container, network blip mid-scan). See
  // util/retry.ts for the full policy — a permanent failure (bad image tag,
  // bad flags) is not retried, and whatever survives still errors and fails
  // the run. We must never silently pass a crash; we also must not fail a
  // build over a 300ms hiccup — nor waste 20 minutes re-running a scan that
  // actually worked, which is why the predicate is per-tool.
  return withRetry(() => exec("docker", runArgs, { timeoutMs }), retryOn);
}

/**
 * On macOS/Windows Docker Desktop, `--network=host` does NOT reach the host's
 * localhost. `host.docker.internal` does. Rewrite a localhost target URL so a
 * container can reach a dev server running on the host.
 */
export function containerReachableUrl(url: string): string {
  return url.replace(
    /^(https?:\/\/)(localhost|127\.0\.0\.1)(:|\/|$)/,
    "$1host.docker.internal$3",
  );
}
