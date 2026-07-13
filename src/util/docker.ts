import { exec, which } from "./exec.js";
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
}

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
  // registry throttle, killed container, network blip mid-scan). See
  // util/retry.ts for the full policy — a permanent failure (bad image tag,
  // bad flags) is not retried, and whatever survives still errors and fails
  // the run. We must never silently pass a crash; we also must not fail a
  // build over a 300ms hiccup.
  return withRetry(
    () => exec("docker", runArgs, { timeoutMs }),
    (r) => r.code !== 0 && (r.timedOut || isTransientFailure(r.stderr || r.stdout)),
  );
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
