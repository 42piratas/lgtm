import { mkdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { hasDocker, dockerRun } from "../util/docker.js";
import { hostOf, isLocalhostUrl } from "../util/http.js";

// TLS/transport assessment via drwetter/testssl.sh in a container.
// Skipped for http/localhost targets (no TLS to inspect). Writes its JSON to a
// host-shared work dir under cwd (Docker Desktop won't bind-mount /var/folders).

const IMAGE = "drwetter/testssl.sh:latest";

const SEVERITY_MAP: Record<string, Finding["severity"]> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  WARN: "low",
};

export const tlsRunner: Runner = {
  id: "tls",
  domain: "transport",
  title: "TLS / transport security",
  requires: { target: true, docker: true },
  async run(ctx: RunnerContext): Promise<RunnerResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;

    if (!url.startsWith("https://") || isLocalhostUrl(url)) {
      return skip(this, start, "no TLS to inspect (http/localhost target)");
    }
    if (!(await hasDocker())) {
      return skip(this, start, "docker unavailable (testssl.sh image needs it)");
    }

    const host = hostOf(url);
    const work = join(process.cwd(), "reports", ".work", `tls-${ctx.run.stamp}`);
    mkdirSync(work, { recursive: true });
    try {
      await dockerRun({
        image: IMAGE,
        args: [
          "--quiet",
          "--fast",
          "--severity",
          "LOW",
          "--jsonfile",
          "/wrk/out.json",
          host,
        ],
        mountsRW: { "/wrk": work },
        // testssl runs as an unprivileged uid inside; make the dir writable.
        extra: ["--user", "0"],
        timeoutMs: 300_000,
      });

      const outPath = join(work, "out.json");
      if (!existsSync(outPath)) {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          note: "testssl.sh wrote no JSON (image/network/mount issue)",
          findings,
          durationMs: Date.now() - start,
        };
      }

      // The file existing is not the same guarantee as it containing a real
      // result: a killed/truncated write leaves a file that exists but
      // isn't valid JSON. Silently treating that as "parsed to nothing" (as
      // this code used to) is the same "absence of evidence" bug as every
      // other runner here — it must error, not report a clean scan.
      let parsed: Array<{ id: string; severity: string; finding: string }>;
      try {
        const raw = JSON.parse(readFileSync(outPath, "utf8"));
        // Flat --jsonfile is an array; --jsonfile-pretty nests under scanResult.
        parsed = Array.isArray(raw) ? raw : (raw?.scanResult ?? []);
      } catch (err) {
        return {
          runnerId: this.id,
          domain: this.domain,
          status: "error",
          note: `testssl.sh wrote unparseable JSON: ${(err as Error).message}`,
          findings,
          durationMs: Date.now() - start,
        };
      }

      // Defense in depth: even with --ip=one, collapse any (id, finding)
      // pair testssl reports more than once rather than trust a single flag
      // to be the only thing standing between us and a duplicated report.
      const seen = new Set<string>();
      for (const item of parsed) {
        const sev = SEVERITY_MAP[item.severity?.toUpperCase?.() ?? ""];
        if (!sev) continue; // OK / INFO
        const key = `${item.id}::${item.finding}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `tls-${item.id}`,
          title: `${item.id}: ${item.finding}`.slice(0, 200),
          severity: sev,
          standard: "testssl.sh / TLS best practice (Mozilla intermediate)",
          location: host,
        });
      }

      if (findings.length === 0) {
        findings.push({
          id: "tls-ok",
          title: "No TLS issues at LOW+ severity",
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
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
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
