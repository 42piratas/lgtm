// lgtm — shared contracts.
//
// A Runner probes one domain (headers, a11y, secrets, …) and returns Findings.
// The orchestrator selects runners, resolves their capability requirements,
// runs them, and the reporter scores + renders the aggregate.

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
  run(ctx: RunnerContext): Promise<RunnerResult>;
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
  /** Runner ids to skip for this site. */
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
  /** Overall pass/fail against the site's failOn threshold. */
  passed: boolean;
  failOn: Severity;
}
