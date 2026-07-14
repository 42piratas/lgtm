import { existsSync } from "node:fs";
import pc from "picocolors";
import type {
  AuditReport,
  Capabilities,
  Runner,
  RunnerContext,
  RunnerResult,
  SiteConfig,
  RunContext,
} from "./types.js";
import { ALL_RUNNERS } from "./runners/index.js";
import { resolveUrls } from "./config.js";
import { hasDocker } from "./util/docker.js";
import { isLocalhostUrl } from "./util/http.js";
import { tallySeverities, computePass, realFindings } from "./scoring.js";

export interface OrchestratorOptions {
  site: SiteConfig;
  /** Effective base URL (config or --url). */
  baseUrl: string;
  outDir: string;
  stamp: string;
  allowActive: boolean;
  /** Explicit runner subset (--only); defaults to all not in site.skip. */
  only?: string[];
  log?: (msg: string) => void;
}

/** Decide whether a runner can run given site config + host capabilities. */
function gate(
  runner: Runner,
  site: SiteConfig,
  caps: Capabilities,
  run: RunContext,
): { ok: true } | { ok: false; note: string } {
  const req = runner.requires;
  if (req.repo && !site.repoPath) {
    return { ok: false, note: "no repoPath configured (white-box runner)" };
  }
  if (req.repo && site.repoPath && !existsSync(site.repoPath)) {
    return { ok: false, note: `repoPath does not exist: ${site.repoPath}` };
  }
  if (req.localhostOnly && !run.isLocalhost) {
    return { ok: false, note: "runner is localhost-only" };
  }
  return { ok: true };
}

export async function runAudit(opts: OrchestratorOptions): Promise<AuditReport> {
  const log = opts.log ?? (() => {});
  const startedAt = new Date().toISOString();

  const run: RunContext = {
    baseUrl: opts.baseUrl,
    isLocalhost: isLocalhostUrl(opts.baseUrl),
    allowActive: opts.allowActive,
    outDir: opts.outDir,
    stamp: opts.stamp,
  };

  const caps: Capabilities = {
    docker: await hasDocker(),
    browser: true,
  };

  const urls = resolveUrls(opts.baseUrl, opts.site.routes);

  const selected = opts.only?.length
    ? ALL_RUNNERS.filter((r) => opts.only!.includes(r.id))
    : ALL_RUNNERS.filter((r) => !(opts.site.skip ?? []).includes(r.id));

  const ctx: RunnerContext = {
    site: opts.site,
    run,
    urls,
    caps,
    log,
  };

  const results: RunnerResult[] = [];
  for (const runner of selected) {
    const g = gate(runner, opts.site, caps, run);
    if (!g.ok) {
      log(`${pc.dim("skip")}  ${runner.id} — ${g.note}`);
      results.push({
        runnerId: runner.id,
        domain: runner.domain,
        status: "skipped",
        note: g.note,
        findings: [],
        durationMs: 0,
      });
      continue;
    }
    log(`${pc.cyan("run ")}  ${runner.id} — ${runner.title}`);
    try {
      const res = await runner.run(ctx);
      const n = realFindings(res.findings).length;
      const tag =
        res.status === "error"
          ? pc.red("err ")
          : res.status === "skipped"
            ? pc.yellow("skip")
            : n > 0
              ? pc.yellow(`${n} issue${n === 1 ? "" : "s"}`)
              : pc.green("clean");
      log(`      ↳ ${tag} ${res.note ? pc.dim(`(${res.note})`) : ""} ${pc.dim(`${res.durationMs}ms`)}`);
      results.push(res);
    } catch (err) {
      log(`      ↳ ${pc.red("crash")} ${(err as Error).message}`);
      results.push({
        runnerId: runner.id,
        domain: runner.domain,
        status: "error",
        note: (err as Error).message,
        findings: [],
        durationMs: 0,
      });
    }
  }

  const totals = tallySeverities(results);
  const passed = computePass(results, opts.site.failOn);

  return {
    site: opts.site.name,
    label: opts.site.label,
    baseUrl: opts.baseUrl,
    stamp: opts.stamp,
    startedAt,
    finishedAt: new Date().toISOString(),
    isLocalhost: run.isLocalhost,
    allowActive: opts.allowActive,
    results,
    totals,
    passed,
    failOn: opts.site.failOn,
  };
}
