import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { derive } from "../../src/scoring.js";
import { secretsRunner } from "../../src/runners/secrets.js";
import { depsRunner } from "../../src/runners/deps.js";
import { sastRunner } from "../../src/runners/sast.js";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// Does the scanner actually find the thing?
//
// Every other test in this repo hands a runner a fixture and checks it parses.
// None of them can tell you whether the command we send the real tool asks for
// the report in a place the real tool will actually put it. That gap is not
// hypothetical: `secrets` requested its report on `--report-path /dev/stdout`,
// which gitleaks accepts and ignores, so the runner returned zero findings for
// every repository it was ever pointed at — including one with two AWS keys
// committed in plaintext — while its unit tests stayed green throughout.
//
// So: plant a real secret in a real git repo, run the real gitleaks image, and
// insist we see it. Same for the other white-box scanners. Nothing is mocked
// here. If a flag is wrong, this is where it dies.

const REPO_ROOT = mkdtempSync(join(tmpdir(), "lgtm-int-"));

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", args, {
    cwd,
    stdio: "ignore",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "lgtm",
      GIT_AUTHOR_EMAIL: "lgtm@example.com",
      GIT_COMMITTER_NAME: "lgtm",
      GIT_COMMITTER_EMAIL: "lgtm@example.com",
    },
  });
}

function repoWith(files: Record<string, string>, name: string): string {
  const dir = join(REPO_ROOT, name);
  mkdirSync(dir, { recursive: true });
  git(dir, "init", "-q");
  for (const [f, body] of Object.entries(files)) {
    writeFileSync(join(dir, f), body);
  }
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "seed");
  return dir;
}

function ctx(repoPath: string): RunnerContext {
  const baseUrl = "http://localhost:1";
  const site: SiteConfig = {
    name: "int",
    baseUrl,
    repoPath,
    routes: [],
    auth: { type: "none" },
    failOn: "high",
  };
  return {
    site,
    run: { baseUrl, isLocalhost: true, allowActive: false, outDir: REPO_ROOT, stamp: "int" },
    urls: [baseUrl],
    caps: { docker: true, browser: false },
    log: () => {},
  };
}

// Not a real credential: a syntactically-valid AWS key pair, generated for this
// test. gitleaks' own rules allowlist the AWS documentation examples
// (AKIAIOSFODNN7EXAMPLE), so using those would have "proved" the scanner works
// while it silently found nothing — the very failure mode this file exists for.
//
// Assembled from fragments so this source file carries no contiguous match: a
// secret scanner run over lgtm's own repository (including the fleet-wide gate,
// which does exactly that) must not trip on the bait we plant for it. The
// runtime value is identical to the committed key — only the literal is split.
const PLANTED_AWS_KEY = "AKIA" + "2E0A8F3B244C9986";
const PLANTED_AWS_SECRET = ["kR8mZq3X", "v7Tn2Wc5", "Yb1Ld9Pf", "4Hs6Jg0U", "w8Qe3Rt"].join("");

let leakyRepo: string;
let cleanRepo: string;
let onePackageRepo: string;

beforeAll(() => {
  leakyRepo = repoWith(
    {
      "creds.txt": `aws_key = ${PLANTED_AWS_KEY}\naws_secret = "${PLANTED_AWS_SECRET}"\n`,
    },
    "leaky",
  );
  cleanRepo = repoWith({ "README.md": "# nothing to see here\n" }, "clean");
  onePackageRepo = repoWith(
    {
      "package.json": JSON.stringify({
        name: "one",
        version: "1.0.0",
        dependencies: { "left-pad": "1.3.0" },
      }),
      // A lockfile resolving to exactly ONE package. osv-scanner then reports
      // "found 1 package" — singular — and a coverage parser insisting on the
      // plural would conclude nothing was scanned and refuse a healthy repo.
      "package-lock.json": JSON.stringify({
        name: "one",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": { name: "one", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } },
          "node_modules/left-pad": {
            version: "1.3.0",
            resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
          },
        },
      }),
    },
    "onepkg",
  );
});

afterAll(() => {
  rmSync(REPO_ROOT, { recursive: true, force: true });
});

describe("secrets — the scanner must actually find a planted secret", () => {
  it("finds the AWS key committed to the repository, and reports it critical", async () => {
    const r = await derive(secretsRunner, ctx(leakyRepo));

    expect(r.status).toBe("ok"); // the scan is sound; the REPO is not
    const critical = r.findings.filter((f) => f.severity === "critical");
    expect(
      critical.length,
      "gitleaks reported no secrets in a repo containing a committed AWS key pair. " +
        "The scan ran and the coverage looks healthy, which means we are asking the " +
        "tool for its report somewhere it does not write one. This is the false " +
        "clean, at its most dangerous.",
    ).toBeGreaterThan(0);
    // gitleaks classifies this pair under `generic-api-key`, not an AWS-specific
    // rule — which is exactly why the assertion above is about FINDING the
    // secret, not about what the tool decided to call it.
    expect(critical.some((f) => f.location?.includes("creds.txt"))).toBe(true);
    // Redacted: the finding must never carry the credential itself.
    const rendered = JSON.stringify(r.findings);
    expect(rendered).not.toContain(PLANTED_AWS_SECRET);
    expect(rendered).not.toContain(PLANTED_AWS_KEY);
  });

  it("reports a genuinely clean repository as clean, with its history on record", async () => {
    const r = await derive(secretsRunner, ctx(cleanRepo));
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(Number(r.coverage?.data.commits)).toBeGreaterThan(0);
    expect(Number(r.coverage?.data.bytes)).toBeGreaterThan(0);
  });

  it("REFUSES a directory that is not a git repository — 0 commits is not 'no secrets'", async () => {
    const notARepo = join(REPO_ROOT, "not-a-repo");
    mkdirSync(notARepo, { recursive: true });
    writeFileSync(join(notARepo, "creds.txt"), `aws_key = ${PLANTED_AWS_KEY}\n`);
    const r = await derive(secretsRunner, ctx(notARepo));
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/0 commits/i);
  });
});

describe("deps — coverage is read from what osv-scanner says it walked", () => {
  it("accepts a lockfile resolving to a single package — 'found 1 package', singular", async () => {
    const r = await derive(depsRunner, ctx(onePackageRepo));
    expect(
      r.status,
      "osv-scanner walked the lockfile, but the runner refused for lack of evidence — " +
        "its coverage parser missed the singular form and concluded nothing was scanned.",
    ).toBe("ok");
    expect(r.coverage?.data.sources).toBe(1);
    expect(r.coverage?.data.packages).toBe(1);
  });

  it("PASSES a repo with no manifest at all — no dependency tree means nothing to audit, not a coverage hole", async () => {
    // The real osv-scanner walks this README-only repo and finds no package
    // sources. That is not a failure: there is genuinely nothing to audit, so
    // the runner passes it clean. (The opposite case — a manifest present but
    // walked to zero sources — is a coverage hole and still errors; that path
    // is exercised in the unit suite where the manifest presence is controlled.)
    const r = await derive(depsRunner, ctx(cleanRepo));
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(r.coverage?.data.manifestPresent).toBe(false);
  });

  it("REFUSES a repo that DECLARES dependencies but resolves none — a manifest with no lockfile is a coverage hole, not a pass", async () => {
    // package.json committed, no lockfile: the real osv-scanner walks zero
    // sources, but the repo plainly has a dependency tree. Passing it would be
    // the false clean this runner exists to prevent, so it must error.
    const manifestNoLockRepo = repoWith(
      { "package.json": JSON.stringify({ name: "declared", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } }) },
      "manifest-no-lock",
    );
    const r = await derive(depsRunner, ctx(manifestNoLockRepo));
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/manifests are present but none were walked/i);
  });
});

describe("sast — semgrep's own file list is the coverage", () => {
  it("reads the file count out of semgrep's real paths.scanned, not out of our assumptions", async () => {
    const r = await derive(sastRunner, ctx(onePackageRepo));
    // Semgrep's rulesets do cover a package.json, so this repo IS scanned. The
    // point is that the number comes from the tool: the runner refuses at zero
    // (unit-tested), and this proves the field it reads is real and populated.
    expect(r.status).toBe("ok");
    expect(Number(r.coverage?.data.filesScanned)).toBeGreaterThan(0);
  });
});
