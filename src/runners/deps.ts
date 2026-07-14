import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun } from "../util/docker.js";
import { readdirSync } from "node:fs";
import { join } from "node:path";

// Dependency CVEs via Google's osv-scanner (container). White-box: needs the
// repo checkout. Reports lockfile-resolved vulnerabilities across ecosystems.

const IMAGE = "ghcr.io/google/osv-scanner:latest";

// Filenames that DECLARE dependencies (manifests) or pin them (lockfiles),
// across every ecosystem osv-scanner resolves. This set only has to answer one
// yes/no question: does this repo have a dependency tree at all? Its presence
// proves there is something to audit; its total absence proves there is not —
// which is what separates a coverage hole from a genuinely dep-free repo.
//
// SAFETY: this must be a SUPERSET of what osv-scanner recognises. A filename osv
// scans but that is missing here would let a repo with real (but unwalked)
// dependencies read as dep-free and PASS — the exact false-clean this runner
// exists to prevent. When osv adds an ecosystem, add its manifest/lockfile here.
// Erring toward inclusion is safe (at worst a false "has deps" → an error to
// investigate); omission is not (a false "dep-free" → a silent pass).
const DEP_FILES = new Set([
  // JavaScript / TypeScript
  "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
  // Ruby
  "Gemfile", "Gemfile.lock", "gems.rb", "gems.locked",
  // Python
  "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock",
  "pdm.lock", "uv.lock", "pylock.toml",
  // Go
  "go.mod", "go.sum",
  // Rust
  "Cargo.toml", "Cargo.lock",
  // Java / Kotlin / JVM
  "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "buildscript-gradle.lockfile",
  "verification-metadata.xml",
  // PHP
  "composer.json", "composer.lock",
  // .NET  (plus *.csproj / *.fsproj / *.vbproj matched by suffix below)
  "packages.config", "packages.lock.json", "deps.json",
  // Dart / Flutter
  "pubspec.yaml", "pubspec.lock",
  // Elixir
  "mix.exs", "mix.lock",
  // C / C++ (Conan)
  "conanfile.txt", "conanfile.py", "conan.lock",
  // R
  "renv.lock",
  // Swift / CocoaPods
  "Package.swift", "Package.resolved", "Podfile", "Podfile.lock",
  // Haskell
  "cabal.project", "cabal.project.freeze", "stack.yaml", "stack.yaml.lock", "package.yaml",
]);
// Project-file extensions whose base name varies per project (.NET, Haskell).
const DEP_SUFFIXES = [".csproj", ".fsproj", ".vbproj", ".cabal"];

// Directories that never hold a repo's OWN declared dependencies, so a manifest
// found inside one is not evidence THIS repo has a dependency tree: vendored
// third-party trees (node_modules/vendor carry foreign manifests), VCS
// internals, generated build output, and this fleet's linked worktree
// checkouts. Note this is intentionally BROADER than the osv-scanner
// --experimental-exclude set below (which only drops node_modules/.git/
// .worktrees): those directories are for the vuln scan, this list is for
// "whose dependency is it". Skipping them can only ever hide a foreign or
// generated manifest, never the repo's own root/src manifest.
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".worktrees", "vendor", "dist", "build", ".next",
]);

// A dep-free repo is walked in full (nothing short-circuits it), so bound the
// walk. On overflow we return TRUE — the safe default: "assume this repo has
// dependencies", which yields an error to investigate rather than a false
// dep-free pass. A tree this large realistically has a manifest anyway.
const MAX_DIRS_WALKED = 50_000;

/**
 * Does the repo contain ANY dependency-declaring file? This is the signal that
 * separates the two ways osv-scanner can walk zero sources — a genuinely
 * dependency-free repo (nothing to audit → clean) versus a repo that declares
 * dependencies but had none of them walked (a lockfile went missing → an
 * ecosystem is unaudited). Short-circuits on the first hit. Directory symlinks
 * are not followed (readdir dirents report them as neither file nor dir), which
 * also makes the walk loop-proof. An unreadable or missing root reads as "no
 * manifest" — the safe answer for a truly empty checkout, matching the
 * never-ran refusal that `sufficient()` applies separately.
 */
function hasDependencyManifest(root: string): boolean {
  const stack: string[] = [root];
  let walked = 0;
  while (stack.length) {
    if (++walked > MAX_DIRS_WALKED) return true;
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(join(dir, e.name));
      } else if (DEP_FILES.has(e.name) || DEP_SUFFIXES.some((s) => e.name.endsWith(s))) {
        return true;
      }
    }
  }
  return false;
}

const SEVERITY_MAP = (cvss?: number): Finding["severity"] => {
  if (cvss === undefined) return "medium";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
};

interface OsvOutput {
  results?: Array<{
    source?: { path?: string };
    packages?: Array<{
      package?: { name?: string; version?: string };
      vulnerabilities?: Array<{
        id?: string;
        summary?: string;
        severity?: Array<{ type?: string; score?: string }>;
        database_specific?: { severity?: string };
      }>;
    }>;
  }>;
}

function cvssFrom(v: { severity?: Array<{ score?: string }> }): number | undefined {
  const raw = v.severity?.[0]?.score;
  if (!raw) return undefined;
  // CVSS vector or numeric — extract a base score if present.
  const m = raw.match(/(\d+(\.\d+)?)/);
  return m ? Number(m[1]) : undefined;
}

/**
 * osv-scanner's JSON lists only the sources that HAVE vulnerabilities — a
 * fully clean repo and a repo where the walk found no lockfiles at all both
 * come back as `{"results":[]}`. The proof of work is in the walk log it
 * writes to stderr, one line per manifest it actually parsed:
 *
 *   Scanned /src/package-lock.json file and found 304 packages
 *
 * That line is the only place the tool says what it looked at, so that is
 * where the coverage has to come from.
 */
function walkedSources(stderr: string): Array<{ path: string; packages: number }> {
  const out: Array<{ path: string; packages: number }> = [];
  // "…and found 1 package" — osv-scanner pluralises, so an insistence on the
  // plural would miss every single-dependency manifest, and this runner would
  // then refuse a repo it had genuinely scanned.
  const re = /Scanned (\S+) file and found (\d+) packages?/g;
  for (const m of stderr.matchAll(re)) {
    out.push({ path: m[1]!, packages: Number(m[2]) });
  }
  return out;
}

export const depsRunner: Runner = {
  id: "deps",
  domain: "deps",
  title: "Dependency CVEs (osv-scanner)",
  requires: { repo: true, docker: true },

  /**
   * Zero sources walked has two opposite meanings, and only one is a failure.
   * If the repo DECLARES dependencies somewhere but none were walked, a lockfile
   * went missing and an entire ecosystem is unaudited — the coverage hole this
   * runner exists to catch (a gitignored lockfile is the classic cause, though
   * --no-ignore now rescues that case; what remains is a manifest with no
   * lockfile committed at all). If the repo declares NOTHING — a docs, static,
   * or meta repo with no dependency tree — there is nothing to audit and this is
   * a clean pass, not "insufficient evidence". `manifestPresent`, computed from
   * the checkout in observe(), is what tells the two apart.
   */
  sufficient(cov: Coverage): string | null {
    if (Number(cov.data.sources ?? 0) === 0) {
      // The absence of the manifest probe means observe() never established
      // anything about this repo — coverage from a scan that never ran. That is
      // a refusal, per the evidence contract: "no findings" must never be
      // indistinguishable from "never looked".
      if (!("manifestPresent" in cov.data)) {
        return "no dependency-scan evidence — the scanner left no walk log at all";
      }
      // observe() DID walk the checkout. If it found dependency manifests but
      // the scan resolved none of them, an ecosystem went unaudited — refuse.
      if (cov.data.manifestPresent === true) {
        return "dependency manifests are present but none were walked — a lockfile is missing, so an ecosystem went unaudited";
      }
      // It walked the checkout and confirmed there is no dependency-declaring
      // file at all: a docs/static/meta repo with nothing to audit. A clean
      // pass — not "insufficient evidence".
      return null;
    }
    // Deliberately NOT checking the package count. A manifest that genuinely
    // resolves to zero dependencies (a fresh scaffold) has been audited — there
    // was simply nothing in it. Refusing that would fail a healthy repo, which
    // is the same disservice as passing an unscanned one.
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

    // Read off the checkout, before the scan, whether this repo declares any
    // dependencies at all. sufficient() needs it to tell a dep-free repo (pass)
    // from one whose dependency tree went unwalked (error) — the walk log alone
    // reports "zero sources" for both.
    const manifestPresent = hasDependencyManifest(repo);

    // osv-scanner respects the repo's .gitignore by default. That's correct
    // for build output, but real lockfiles are routinely gitignored too —
    // e.g. a Jekyll repo's Gemfile.lock (42piratas.com) — and get silently
    // excluded from the walk entirely: "No package sources found", the
    // *entire* ecosystem goes unaudited, and it looks like a tool error
    // rather than a coverage hole. --no-ignore restores them. The same
    // gitignore rule ordinarily hides node_modules, .git, and (in this
    // fleet's convention) .worktrees/ — --no-ignore would otherwise pull
    // those back in too (vendor noise, or duplicate scans of stale worktree
    // checkouts), so exclude them explicitly instead.
    const r = await dockerRun({
      image: IMAGE,
      args: [
        "scan",
        "source",
        "--recursive",
        "--no-ignore",
        "--experimental-exclude",
        "r:node_modules",
        "--experimental-exclude",
        "r:\\.git",
        "--experimental-exclude",
        "r:\\.worktrees",
        "--format",
        "json",
        "/src",
      ],
      mounts: { "/src": repo },
      timeoutMs: 300_000,
    });

    const sources = walkedSources(r.stderr);

    const emptyCoverage: Coverage = {
      trail: ["walked no lockfile or manifest"],
      data: { sources: 0, packages: 0, manifestPresent },
      provenance: "osv-scanner walk log (stderr)",
    };

    // A repo with nothing to scan is osv-scanner's exit 128, "No package sources
    // found". That is not a broken tool — the tool worked perfectly and found
    // nothing to look at, which is a COVERAGE fact, not an error. Reporting it
    // as "osv-scanner error (exit 128)" sent the operator hunting a container
    // problem when the real answer is that a lockfile is gitignored and an
    // entire ecosystem is going unaudited. Hand it to sufficient(), which says
    // so in as many words.
    if (/no package sources found/i.test(r.stderr)) {
      return { kind: "observed", findings, coverage: emptyCoverage };
    }

    // osv-scanner exits 1 when vulns are found, 0 when clean, >1 on real error.
    if (r.code > 1 && !r.stdout.trim().startsWith("{")) {
      return {
        kind: "failed",
        note: `osv-scanner error (exit ${r.code}): ${r.stderr.slice(0, 300)}`,
      };
    }

    // A clean osv-scanner JSON run always emits at least `{"results":[]}` —
    // if stdout has no `{` at all, or what follows it doesn't parse, the
    // tool didn't produce real output (crash, OOM, truncated write). That is
    // "unknown", not "zero vulnerabilities": silently falling through to an
    // empty `out` here is exactly how a dead scanner reports a clean pass.
    const s = r.stdout.indexOf("{");
    if (s < 0) {
      return {
        kind: "failed",
        note: `osv-scanner produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
      };
    }
    let out: OsvOutput;
    try {
      out = JSON.parse(r.stdout.slice(s));
    } catch (err) {
      return {
        kind: "failed",
        note: `osv-scanner produced unparseable JSON: ${(err as Error).message}`,
      };
    }

    for (const result of out.results ?? []) {
      for (const pkg of result.packages ?? []) {
        for (const v of pkg.vulnerabilities ?? []) {
          const cvss = cvssFrom(v);
          findings.push({
            id: `dep-${v.id ?? "unknown"}`,
            title: `${pkg.package?.name}@${pkg.package?.version}: ${v.id} — ${(v.summary ?? "").slice(0, 120)}`,
            severity: SEVERITY_MAP(cvss),
            standard: "OSV / GHSA",
            location: result.source?.path,
            remediation: `Upgrade ${pkg.package?.name} to a non-vulnerable version.`,
            evidence: v.id ? `https://osv.dev/vulnerability/${v.id}` : undefined,
          });
        }
      }
    }

    const packages = sources.reduce((n, s2) => n + s2.packages, 0);

    return {
      kind: "observed",
      findings,
      coverage: {
        trail: sources.map(
          (s2) => `walked ${s2.path.replace(/^\/src\/?/, "")} — ${s2.packages} packages`,
        ),
        data: { sources: sources.length, packages, manifestPresent },
        provenance: "osv-scanner walk log (stderr)",
      },
      meta: { sources: sources.map((s2) => s2.path), packages },
    };
  },
};
