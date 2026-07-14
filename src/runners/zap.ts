import { mkdirSync, readFileSync, existsSync, rmSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import {
  dockerRun,
  containerReachableUrl,
  transientInfraFailureUnless,
} from "../util/docker.js";
import { probeTarget } from "../util/authgate.js";

// Dynamic scan via OWASP ZAP (container).
//   * passive baseline — safe, runs against any reachable target.
//   * active full-scan — mutating/attacking; ONLY when the target is localhost
//     AND the operator passed --allow-active.

const IMAGE = "ghcr.io/zaproxy/zaproxy:stable";

const RISK_MAP: Record<string, Finding["severity"]> = {
  "3": "high",
  "2": "medium",
  "1": "low",
  "0": "info",
};

interface ZapReport {
  site?: Array<{
    alerts?: Array<{
      alert?: string;
      riskcode?: string;
      desc?: string;
      solution?: string;
      instances?: Array<{ uri?: string }>;
    }>;
  }>;
}

/**
 * ZAP's JSON report carries alerts and nothing else — it cannot tell you
 * whether the spider reached one page or a hundred, and a scan that crawled
 * nothing produces the same empty alert list as a spotless site. Its stdout
 * does say, though:
 *
 *   Total of 12 URLs                                 (needs -d)
 *   FAIL-NEW: 0  ...  INFO: 3  IGNORE: 0  PASS: 58   (always printed)
 *
 * `PASS` counts the passive rules that ran and matched nothing — proof the
 * rule engine actually executed. Both are read here; neither is inferred.
 */
function crawlLog(stdout: string): { urls: number; rules: number } {
  const urls = stdout.match(/Total of (\d+) URLs/);
  const tally = stdout.match(
    /FAIL-NEW:\s*(\d+)\s+FAIL-INPROG:\s*(\d+)\s+WARN-NEW:\s*(\d+)\s+WARN-INPROG:\s*(\d+)\s+INFO:\s*(\d+)\s+IGNORE:\s*(\d+)\s+PASS:\s*(\d+)/,
  );
  const rules = tally
    ? tally.slice(1).reduce((n, x) => n + Number(x), 0)
    : 0;
  return { urls: urls ? Number(urls[1]) : 0, rules };
}

export const zapRunner: Runner = {
  id: "zap",
  domain: "dast",
  title: "Dynamic scan (OWASP ZAP)",
  requires: { target: true, docker: true },

  /**
   * A dynamic scan is only worth as much as the surface it reached. Zero
   * spidered URLs means ZAP never got into the app (unreachable host, a JS-only
   * shell with no crawlable links, a login wall) — and its silence about that
   * app is not a clean result.
   */
  sufficient(cov: Coverage): string | null {
    if (Number(cov.data.urlsSpidered ?? 0) === 0) {
      return "the spider reached 0 URLs — the app was never crawled";
    }
    if (Number(cov.data.rulesRun ?? 0) === 0) {
      return "no scan rules ran against the crawled pages";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];

    // Refuse before spending a ZAP container run on content that isn't the
    // site: an auth-gate redirect or a non-2xx/3xx response.
    const probe = await probeTarget(ctx.run.baseUrl);
    if (!probe.ok) {
      return { kind: "failed", note: probe.note };
    }

    const active = ctx.run.isLocalhost && ctx.run.allowActive;
    const script = active ? "zap-full-scan.py" : "zap-baseline.py";
    const target = containerReachableUrl(ctx.run.baseUrl);
    // Work dir under cwd — Docker Desktop won't bind-mount /var/folders tmp.
    const workDir = join(process.cwd(), "reports", ".work", `zap-${ctx.run.stamp}`);
    mkdirSync(workDir, { recursive: true });
    // ZAP runs as its built-in uid 1000; make the bind-mount writable to it.
    chmodSync(workDir, 0o777);
    const reportName = "report.json";
    const reportPath = join(workDir, reportName);

    const r = await dockerRun({
      image: IMAGE,
      // -d (detailed) is what makes ZAP print "Total of N URLs". Without it the
      // spider's reach is unknowable, and an empty report is unreadable: it
      // could mean a clean app or an app that was never crawled at all.
      args: [script, "-t", target, "-J", reportName, "-I", "-d"],
      mountsRW: { "/zap/wrk": workDir },
      extra: ["--add-host=host.docker.internal:host-gateway"],
      timeoutMs: active ? 1_200_000 : 420_000,
      // ZAP ALWAYS exits nonzero when it finds alerts — that is a successful
      // scan, not a failure — and its stdout is full of alert text that can
      // legitimately mention a 500 it deliberately elicited. Retrying on that
      // would re-run a full scan (up to 20 minutes) to reach the same answer.
      // The report file is the ground truth: if it's there, we're done.
      retryOn: transientInfraFailureUnless(() => existsSync(reportPath)),
    });
    const crawl = crawlLog(r.stdout);

    if (!existsSync(reportPath)) {
      rmSync(workDir, { recursive: true, force: true });
      return {
        kind: "failed",
        note: `ZAP produced no report (exit ${r.code}): ${r.stderr.slice(0, 250)}`,
      };
    }

    // The report file existing doesn't mean it's valid: a killed/truncated
    // write leaves a file present but not parseable JSON. That must error
    // like every other "tool didn't actually report anything" case here —
    // not fall through as a silent "no alerts".
    let report: ZapReport;
    try {
      report = JSON.parse(readFileSync(reportPath, "utf8"));
    } catch (err) {
      rmSync(workDir, { recursive: true, force: true });
      return {
        kind: "failed",
        note: `ZAP report was not parseable JSON: ${(err as Error).message}`,
      };
    }
    rmSync(workDir, { recursive: true, force: true });

    const seen = new Set<string>();
    for (const site of report.site ?? []) {
      for (const a of site.alerts ?? []) {
        const sev = RISK_MAP[a.riskcode ?? "0"] ?? "info";
        if (sev === "info") continue;
        const key = a.alert ?? "";
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `zap-${(a.alert ?? "alert").toLowerCase().replace(/\W+/g, "-").slice(0, 40)}`,
          title: `${a.alert} (${a.instances?.length ?? 0} instance${a.instances?.length === 1 ? "" : "s"})`,
          severity: sev,
          standard: "OWASP ZAP",
          location: a.instances?.[0]?.uri ?? ctx.run.baseUrl,
          remediation: (a.solution ?? "").replace(/<[^>]+>/g, "").slice(0, 200),
          evidence: (a.desc ?? "").replace(/<[^>]+>/g, "").slice(0, 200),
        });
      }
    }

    return {
      kind: "observed",
      note: active
        ? "active full-scan"
        : "passive baseline (pass --allow-active on localhost for active)",
      findings,
      coverage: {
        trail: [
          `${active ? "active full-scan" : "passive baseline"} of ${ctx.run.baseUrl}`,
          `spider reached ${crawl.urls} URL${crawl.urls === 1 ? "" : "s"}`,
          `${crawl.rules} scan rule${crawl.rules === 1 ? "" : "s"} ran against them`,
        ],
        data: { urlsSpidered: crawl.urls, rulesRun: crawl.rules, active },
        provenance: "zap-baseline URL count + rule tally (stdout)",
      },
      meta: { urlsSpidered: crawl.urls, rulesRun: crawl.rules },
    };
  },
};
