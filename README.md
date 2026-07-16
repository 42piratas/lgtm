# lgtm

> _"looks good to me"_ — except this one actually checks.

A config-driven audit harness that runs current best-practice **security,
accessibility, privacy, and quality** checks against **any** website — **locally,
before you launch**, and re-pointable at a live URL. One config per site, one
command, one scored HTML + JSON report with a CI-gating exit code.

lgtm doesn't reinvent scanners — it **orchestrates** best-of-breed OSS tools
behind a single authenticated, local-first workflow and a unified report.

## What it checks

| Runner | Domain | Standard | Mode | Tool |
|---|---|---|---|---|
| `headers` | security | OWASP Secure Headers, CSP L3, RFC 6797 | black-box | native |
| `tls` | transport | Mozilla intermediate TLS | black-box | testssl.sh (docker) |
| `cookies` | privacy | OWASP ASVS 3.4 / 4.2 (CSRF) | black-box | native |
| `a11y` | accessibility | **WCAG 2.2 AA incl. color contrast** | black-box (authed) | axe-core + Playwright |
| `authz` | access control | OWASP Top 10 A01, ASVS 8.3 | black-box (authed) | Playwright |
| `lighthouse` | perf/SEO | Core Web Vitals | black-box (authed) | Lighthouse |
| `deps` | supply chain | OSV / GHSA | white-box | osv-scanner (docker) |
| `secrets` | secrets | OWASP ASVS 2.10 | white-box | gitleaks (docker) |
| `sast` | static analysis | OWASP Top 10, CWE | white-box | Semgrep (docker) |
| `zap` | DAST | OWASP ZAP | black-box | ZAP (docker) |

**Black-box** runners need only a reachable URL. **White-box** runners need the
repo checkout (`repoPath` in the site config). Docker-hosted scanners need
Docker running.

A runner that cannot run does **not** quietly drop out: the domain it covers
went unaudited, and the run fails. If that is intentional — you genuinely do not
want ZAP against this site — waive it explicitly with `skip:` in the site
config. The waiver is reported; the run can still pass.

That is the rule the whole tool is built around:

> **A scan that examined nothing is not a clean scan.** Every runner reports
> what it actually looked at — lockfiles walked, commits read, URLs spidered,
> pages rendered — and a verdict of "clean" is *derived* from that evidence,
> never asserted by the scanner itself. No evidence, no pass.

So `lgtm` goes red on things a scanner usually goes green on: a secret scan
pointed at a directory that isn't a git repo, a dependency scan whose only
lockfile is gitignored, a Semgrep run over a language its rulesets don't parse,
a ZAP baseline whose spider never got past the front door, an axe audit of a
page that rendered an empty body. Each of those exits 0 and reports nothing. None
of them looked at anything. Every report states its own coverage, so you can
check the claim rather than take it.

## Setup

```bash
cd lgtm
npm install          # also installs the Chromium Playwright needs
# Docker Desktop running unlocks tls / deps / secrets / sast / zap
```

## Configure a site

Copy the template and edit it — real site configs are git-ignored, so yours stay
local:

```bash
cp sites/example.yaml sites/mysite.yaml
$EDITOR sites/mysite.yaml
```

`baseUrl` is required; `repoPath` unlocks the white-box scanners;
`auth.type: storageState` unlocks authenticated coverage.

## Run

```bash
# 1. Start your dev server (e.g. on :3000), then:
npm run audit -- run mysite

# Re-point at any URL (prod sweep, staging, preview):
npm run audit -- run mysite --url https://example.com

# Subset of checks:
npm run audit -- run mysite --only headers,a11y,cookies

# Active/attacking DAST — localhost ONLY, opt-in:
npm run audit -- run mysite --allow-active

npm run audit -- list      # runners + configured sites
```

The report lands in `reports/<site>/<site>-<stamp>.html` (+ `.json` for CI). Exit
code is `0` on pass, `1` when any finding meets the site's `failOn` threshold —
wire it into CI as a gate.

## Authenticated surfaces

Most apps live behind login. Capture a session once — the harness reuses it for
`a11y`, `authz`, and `lighthouse` so they see the real, logged-in app:

```bash
npm run audit -- auth mysite     # opens a browser; log in; press Enter
```

The session is written to `.auth/<site>.json` (git-ignored, never committed). The
`authz` runner then verifies protected routes actually enforce auth (anonymous
access → high finding), authed responses aren't cacheable, and cookies are sound.

## Tuning for large repos

Some runners scan the whole repository and can hit their container time budget on
very large targets (thousands of commits, 100 MB+ history). They **fail closed**
(a killed scan is "unknown", never "clean"), so a too-short budget shows up as a
gate failure, not a silent pass. Raise the budget without a rebuild:

| Env var | Runner | Default | Raise it when |
|---|---|---|---|
| `LGTM_SECRETS_TIMEOUT_MS` | `secrets` (gitleaks, full-history scan) | `900000` (15 min) | the gate reports `gitleaks timed out after …s scanning full history` |

`sast` (semgrep) is separately bounded for memory/parallelism on large repos (see
`src/runners/sast.ts`).

## Safety

- Active/mutating scans (`zap-full-scan`) run **only** against localhost and
  **only** with `--allow-active`. Against any remote target the harness refuses,
  and ZAP falls back to a passive baseline.
- Captured sessions, reports, and your real site configs are all git-ignored.

## License

Open source — [AGPL-3.0](LICENSE). Commercial — contact ahoy@42labs.io.

---
If it earned its keep, [coffee is appreciated](https://buymeacoffee.com/42piratas). ☕
