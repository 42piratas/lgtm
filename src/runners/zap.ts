import { mkdirSync, readFileSync, existsSync, rmSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { hasDocker, dockerRun, containerReachableUrl } from "../util/docker.js";
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

export const zapRunner: Runner = {
  id: "zap",
  domain: "dast",
  title: "Dynamic scan (OWASP ZAP)",
  requires: { target: true, docker: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Refuse before spending a ZAP container run on content that isn't the
    // site: an auth-gate redirect or a non-2xx/3xx response.
    const probe = await probeTarget(ctx.run.baseUrl);
    if (!probe.ok) {
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: probe.note,
        findings,
        durationMs: Date.now() - start,
      };
    }

    if (!(await hasDocker())) {
      return skip(this, start, "docker unavailable (ZAP image needs it)");
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

    const r = await dockerRun({
      image: IMAGE,
      args: [script, "-t", target, "-J", reportName, "-I"],
      mountsRW: { "/zap/wrk": workDir },
      extra: ["--add-host=host.docker.internal:host-gateway"],
      timeoutMs: active ? 1_200_000 : 420_000,
    });

    const reportPath = join(workDir, reportName);
    if (!existsSync(reportPath)) {
      rmSync(workDir, { recursive: true, force: true });
      return {
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `ZAP produced no report (exit ${r.code}): ${r.stderr.slice(0, 250)}`,
        findings,
        durationMs: Date.now() - start,
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
        runnerId: this.id,
        domain: this.domain,
        status: "error",
        note: `ZAP report was not parseable JSON: ${(err as Error).message}`,
        findings,
        durationMs: Date.now() - start,
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

    if (findings.length === 0) {
      findings.push({
        id: "zap-ok",
        title: `ZAP ${active ? "active" : "passive"} scan found no low+ alerts`,
        severity: "info",
      });
    }

    return {
      runnerId: this.id,
      domain: this.domain,
      status: "ok",
      note: active ? "active full-scan" : "passive baseline (pass --allow-active on localhost for active)",
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
