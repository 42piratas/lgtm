// lgtm — shared contracts.
//
// A Runner probes one domain (headers, a11y, secrets, …) and reports what it
// SAW: findings plus the coverage that backs them. It never says whether that
// is good enough. The orchestrator alone turns an observation into a verdict,
// by asking the runner's own `sufficient()` rule whether the coverage supports
// a conclusion at all, and refusing when it does not.
//
// The rule this encodes: "no findings" is only "clean" if we can show the tool
// actually looked. Absence of evidence is not evidence of absence — and a
// runner is never allowed to assert its own pass.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Broad category a runner belongs to — drives the report's section grouping. */
export type Domain =
  | "security" // headers, CSP, transport
  | "transport" // TLS
  | "a11y" // WCAG 2.2
  | "perf" // Core Web Vitals, best-practice, SEO
  | "privacy" // cookies, trackers, CSRF
  | "deps" // dependency CVEs
  | "secrets" // leaked credentials
  | "sast" // static analysis
  | "dast" // dynamic active scan
  | "authz"; // authenticated crawl + session hygiene

/** A single issue (or an explicit pass note when severity === "info"). */
export interface Finding {
  /** Stable slug, unique within a runner: "csp-missing", "contrast-4.5". */
  id: string;
  title: string;
  severity: Severity;
  /** WCAG 2.2 SC, OWASP ASVS id, CWE, RFC — whatever standard backs this. */
  standard?: string;
  /** URL, file:line, selector — where it was observed. */
  location?: string;
  /** Short, actionable fix. */
  remediation?: string;
  /** Raw supporting detail (header value, matched line, node HTML). */
  evidence?: string;
  /**
   * This is not a confirmed pass or fail — a human needs to look. Used e.g.
   * when a contrast checker's input is known-unreliable (-webkit-text-stroke
   * confusing fill color with stroke color). Always paired with
   * severity: "info" (never counted toward failOn/grade) but, unlike a plain
   * pass-note, still rendered in the report — it must not be silently dropped.
   */
  needsReview?: boolean;
}

/**
 * What a runner actually looked at — the receipts behind its findings.
 *
 * This is the whole point of the contract: a scanner that returns zero
 * findings and zero coverage has not found a clean site, it has found
 * nothing, and those two must never render the same. Every runner has to
 * hand back the units of work it genuinely performed, read out of the tool's
 * own output — never inferred, never assumed, never defaulted.
 */
export interface Coverage {
  /**
   * Human-readable receipts, one line per unit of work actually done
   * ("scanned package-lock.json — 304 packages", "GET / → 200"). Rendered
   * verbatim in the report so a reader can check the claim themselves.
   */
  trail: string[];
  /**
   * The machine-checkable counts `sufficient()` reads. Keys are the runner's
   * own ("urls", "commits", "sources", "rules"). Numbers here MUST come from
   * the tool's output, not from what we hoped it would do.
   */
  data: Record<string, number | string | boolean>;
  /** Which tool output the numbers were read out of — stdout, stderr, report file. */
  provenance: string;
}

/**
 * A runner's raw report. Deliberately has NO status field: deciding whether an
 * observation amounts to a pass is the orchestrator's job, not the runner's.
 *
 *   observed      — the tool ran and produced output we could read.
 *   notApplicable — the domain does not exist for this target (no TLS to
 *                   inspect on an http://localhost dev server). Nothing was
 *                   missed, so this does not hold the run back.
 *   unavailable   — the tool could not run here (no Docker, no repo checkout).
 *                   The domain DOES apply and went unaudited: a coverage hole,
 *                   and the run cannot pass on it.
 *   failed        — the tool ran but produced nothing usable (crash, truncated
 *                   output, auth gate, dead page). Not a verdict either.
 *
 * The distinction between the middle two is the load-bearing one. "There is no
 * TLS here" and "we never checked the TLS" both used to render as a grey dash.
 */
export type RunnerOutcome =
  | {
      kind: "observed";
      findings: Finding[];
      coverage: Coverage;
      note?: string;
      meta?: Record<string, unknown>;
    }
  | { kind: "notApplicable"; note: string }
  | { kind: "unavailable"; note: string }
  | { kind: "failed"; note: string; meta?: Record<string, unknown> };

export type RunnerStatus = "ok" | "skipped" | "error";

export interface RunnerResult {
  runnerId: string;
  domain: Domain;
  status: RunnerStatus;
  /** Human note — why skipped, what errored, or a one-line summary. */
  note?: string;
  findings: Finding[];
  /** Wall-clock ms. */
  durationMs: number;
  /** Free-form metrics surfaced in the report (lighthouse scores, counts). */
  meta?: Record<string, unknown>;
  /** The receipts. Present whenever the runner observed anything at all. */
  coverage?: Coverage;
  /**
   * True when this domain went unaudited for an accepted reason: the operator
   * waived the runner (site `skip:` or `--only`), or the domain does not apply
   * to this target at all. An UNexcused absence is a coverage hole and fails
   * the run; an excused one is only reported.
   */
  waived?: boolean;
}

/** What a runner needs present to be able to run. */
export interface RunnerRequirements {
  /** Needs `docker` on PATH (Docker-hosted scanner). */
  docker?: boolean;
  /** Needs a local repo checkout (white-box). */
  repo?: boolean;
  /** Needs a reachable HTTP target (black-box). */
  target?: boolean;
  /** Needs a real browser session (Playwright). */
  browser?: boolean;
  /** Only safe against localhost — active/mutating probes. */
  localhostOnly?: boolean;
}

export interface Runner {
  id: string;
  domain: Domain;
  title: string;
  requires: RunnerRequirements;
  /** Look. Report findings + the coverage behind them. Never judge. */
  observe(ctx: RunnerContext): Promise<RunnerOutcome>;
  /**
   * Is this coverage enough to conclude anything about the domain?
   * Return null when it is, or a short reason when it is not ("spidered 0
   * URLs", "no lockfiles walked"). The orchestrator calls this — a runner
   * cannot skip the question, and cannot answer it about itself.
   */
  sufficient(coverage: Coverage, ctx: RunnerContext): string | null;
}

export type AuthConfig =
  | { type: "none" }
  | {
      // Playwright storageState JSON (cookies + localStorage): capture a
      // logged-in session once with `lgtm auth`, then point lgtm at it.
      type: "storageState";
      path: string;
    };

export interface SiteConfig {
  /** Slug — matches the config filename and `--site`. */
  name: string;
  /** Display name. */
  label?: string;
  /** Base URL probed in black-box runners. Overridable with --url. */
  baseUrl: string;
  /** Absolute path to the repo for white-box runners. Omit → those skip. */
  repoPath?: string;
  /** Additional routes (paths or absolute URLs) to crawl for a11y/perf/authz. */
  routes: string[];
  auth: AuthConfig;
  /** Fail the run (exit 1) if any finding is at or above this severity. */
  failOn: Severity;
  /**
   * Runner ids the operator explicitly waives for this site. A waiver is a
   * decision on the record: the domain is reported as not audited, and the
   * run may still pass. Anything that fails to run WITHOUT a waiver is a
   * coverage hole and fails the run instead.
   */
  skip?: string[];
}

export interface RunContext {
  /** Resolved effective base URL (config.baseUrl or --url override). */
  baseUrl: string;
  /** True when baseUrl host is localhost/127.0.0.1 — unlocks active scans. */
  isLocalhost: boolean;
  /** Operator opted into active/mutating probes (localhost only). */
  allowActive: boolean;
  /** Reports output dir for this run. */
  outDir: string;
  /** ISO-ish stamp used in filenames: YYMMDD-HHMM. */
  stamp: string;
}

export interface RunnerContext {
  site: SiteConfig;
  run: RunContext;
  /** Absolute URLs to probe: baseUrl + each route, de-duped. */
  urls: string[];
  /** Detected capabilities of the host environment. */
  caps: Capabilities;
  log: (msg: string) => void;
}

export interface Capabilities {
  docker: boolean;
  /** Docker images known-present locally (best-effort; pulled on demand). */
  browser: boolean;
}

export interface AuditReport {
  site: string;
  /** Display label from the site config, if any. */
  label?: string;
  baseUrl: string;
  stamp: string;
  startedAt: string;
  finishedAt: string;
  isLocalhost: boolean;
  allowActive: boolean;
  results: RunnerResult[];
  totals: Record<Severity, number>;
  /**
   * Overall pass. Requires BOTH: nothing at or above failOn, AND full
   * coverage. A run that never audited half the domains cannot pass — that
   * is the same false all-clear as a runner asserting its own success, just
   * one level up.
   */
  passed: boolean;
  /** Every runner either produced a verdict or was explicitly waived. */
  complete: boolean;
  /** Domains with no verdict — the coverage holes. Empty on a complete run. */
  notAudited: Array<{ runnerId: string; reason: string; waived: boolean }>;
  failOn: Severity;
}
