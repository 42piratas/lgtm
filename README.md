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
repo checkout (`repoPath` in the site config) and auto-skip without it.
Docker-hosted scanners auto-skip if Docker isn't running — nothing else breaks.

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

## Safety

- Active/mutating scans (`zap-full-scan`) run **only** against localhost and
  **only** with `--allow-active`. Against any remote target the harness refuses,
  and ZAP falls back to a passive baseline.
- Captured sessions, reports, and your real site configs are all git-ignored.

## License

Open source — [AGPL-3.0](LICENSE). Commercial — contact ahoy@42labs.io.

---
If it earned its keep, [coffee is appreciated](https://buymeacoffee.com/42piratas). ☕
