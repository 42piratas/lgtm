import { mkdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { promises as dns } from "node:dns";
import type { Finding, Runner, RunnerContext, RunnerResult } from "../types.js";
import { hasDocker, dockerRun, transientInfraFailureUnless } from "../util/docker.js";
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

/**
 * Which IP to hand testssl.sh, and how many the host actually has.
 *
 * Left to itself, testssl.sh loops the whole scan over EVERY resolved address
 * and concatenates the results — which is what produced the duplicated TLS
 * findings on ds.42labs.io and 42piratas.com (both Cloudflare-fronted, both
 * two A-records). `--ip one` fixes the duplication but picks whichever address
 * comes back first, so the scan is non-deterministic across CI machines and
 * silently says nothing about how many endpoints exist.
 *
 * So we resolve the addresses ourselves and pin the lowest one in sorted
 * order: same host, same IP, same result, on every machine. The count comes
 * back too, so the runner can state its own coverage honestly rather than
 * quietly implying it scanned everything.
 */
async function resolveScanTarget(
  host: string,
): Promise<{ ip: string | null; total: number }> {
  try {
    const [v4, v6] = await Promise.all([
      dns.resolve4(host).catch(() => [] as string[]),
      dns.resolve6(host).catch(() => [] as string[]),
    ]);
    const all = [...v4, ...v6].sort();
    return { ip: all[0] ?? null, total: all.length };
  } catch {
    return { ip: null, total: 0 };
  }
}

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
    // Pin a single, deterministic endpoint (see resolveScanTarget). Falling
    // back to "one" keeps the runner working if DNS resolution fails here but
    // works inside the container.
    const { ip, total } = await resolveScanTarget(host);
    const work = join(process.cwd(), "reports", ".work", `tls-${ctx.run.stamp}`);
    mkdirSync(work, { recursive: true });
    const outPath = join(work, "out.json");
    try {
      await dockerRun({
        image: IMAGE,
        args: [
          "--quiet",
          "--fast",
          // Scan exactly one endpoint, chosen deterministically. Without this,
          // testssl.sh loops over every resolved address and concatenates the
          // results — which is what emitted every TLS finding twice for
          // ds.42labs.io and 42piratas.com (both Cloudflare, both dual-IP).
          // The hostname is still passed as the target, so SNI/cert validation
          // are done against the real name.
          "--ip",
          ip ?? "one",
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
        // testssl signals findings through its exit code, and its own output is
        // a FILE. If out.json exists, the scan ran and answered — retrying it
        // would just burn another couple of minutes to reach the same result.
        retryOn: transientInfraFailureUnless(() => existsSync(outPath)),
      });

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

      // Defense in depth: even pinned to one endpoint, collapse any
      // (id, finding) pair testssl reports more than once rather than trust a
      // single flag to be the only thing standing between us and a duplicated
      // report.
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

      // Say out loud what was and wasn't covered. Scanning one endpoint of a
      // multi-endpoint host is the right default (every edge of a CDN serves
      // the same TLS config, and scanning all of them just duplicates the
      // report) — but "we only looked at one of N" is a fact the operator is
      // entitled to, not something to bury. If the endpoints ever genuinely
      // diverge, this line is the thread to pull.
      if (total > 1 && ip) {
        findings.push({
          id: "tls-endpoint-coverage",
          title: `Scanned 1 of ${total} resolved endpoints for ${host} (${ip}) — a divergent endpoint would not be seen`,
          severity: "info",
          needsReview: true,
          location: host,
          remediation:
            "Normal for a CDN/anycast host, where every edge serves the same TLS configuration. If this host fronts genuinely different origins per address, scan each address explicitly.",
        });
      }

      return {
        runnerId: this.id,
        domain: this.domain,
        status: "ok",
        note: total > 1 ? `1 of ${total} endpoints (${ip})` : undefined,
        findings,
        durationMs: Date.now() - start,
        meta: { endpointScanned: ip, endpointsResolved: total },
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
