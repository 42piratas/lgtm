# Handover: LGTM lies, and patching it one runner at a time is not working

**For:** the next agent taking this on.
**Status of the code:** PR #3 is open and green (260 tests). It fixes six real bugs. **It does not fix the thing that caused them.**
**Your job:** fix the cause. Not a seventh bug.

---

## 1. What actually happened

LGTM was used to audit six live sites. It is a wrapper: it drives ten well-established open-source tools (axe, Lighthouse, ZAP, semgrep, gitleaks, testssl, osv-scanner…) and merges their output into one report with one pass/fail verdict.

**The tools were fine. The wrapper lied.**

Six times, in six different places, it reported **absence of evidence as evidence of absence** — it said "clean" about something it had never actually checked. Each one was found by a *different* review round. None was found by the round before it.

| # | What it did | What it should have done |
|---|---|---|
| 1 | Followed a 302 into Cloudflare Access and **graded the login page** — letter grade, full findings list, presented as the site's report | Refuse: this is not the site |
| 2 | Read a **429** (Vercel bot protection) as **"no security headers"** — on a site that returns all 8 in a real browser | Refuse: findings are unknown, not absent |
| 3 | Reported a **clean scan when semgrep crashed** — empty output, nothing parsed, "No Semgrep findings". Present in **five** runners | Error: the repo was never scanned |
| 4 | Reported **"protected routes enforce auth"** for routes it **never loaded** — nav failures went into an empty `catch` | Error: access control unverified |
| 5 | Waved through genuinely unreadable text — black on `opacity: 0.28` renders ~2.3:1, computed 21:1 on paper | Keep the failure |
| 6 | Reported **"performance scores meet thresholds"** when Lighthouse **returned no data at all** (its API can resolve `undefined` without throwing) | Error: nothing was measured |

All six are fixed, each with a test that fails if it is reintroduced. **That is not the point.**

---

## 2. The actual defect — read this twice

Two structural facts, and everything above follows from them:

### (a) There is no shared contract for "did this tool produce evidence?"

Each of the **ten runners hand-rolls that judgement itself**. There is no single place that asks *"did the underlying tool actually answer?"* before a verdict is allowed.

That is why the same mistake had to be found **six separate times, one runner at a time**. It is why every review round found another one. It is why you should assume a seventh exists.

### (b) "Clean" is the default

**8 of the 10 runners** end with some version of:

```ts
if (findings.length === 0) {
  findings.push({ id: "…-ok", title: "…all good…", severity: "info" });
}
return { status: "ok", findings, … };
```

So *any* path that fails to collect findings — a crash, an empty file, a null response, a 429, a swallowed exception, an early return — **falls through to "all good."**

The failure mode is the fallthrough. Nobody wrote "report clean when the tool crashes." They wrote "report clean when there are no findings," and then a crash produced no findings.

---

## 3. What we want instead

**Invert the default. Make the lie structurally impossible, rather than something we audit for.**

The shape (design it properly — this is a sketch, not a spec):

- A runner **cannot return a verdict**. It returns **evidence**: what it fetched, what the tool exited with, what it parsed, how many things it examined.
- **A single shared gate** turns evidence into a verdict. No evidence → no verdict. Not "clean" — *unknown*, and unknown fails the build.
- "I checked N things and found nothing wrong" and "I checked nothing" must be **different types**, not the same empty array. Today they are indistinguishable, and that is the whole bug.
- Make it **impossible to construct a passing result without evidence** — enforce it in the type system if you can, so the compiler rejects the bug rather than a reviewer catching it on round seven.

**The test for whether you've succeeded:** take any of the six bugs above, try to reintroduce it, and find that you *can't express it* — not that a test catches it.

---

## 4. What is already done — don't redo it

PR #3 (open, green, 260 tests, contains PR #2's test suite):

- All six bugs above, fixed, each with a regression test.
- **Test suite from zero** — 260 tests, ~1.4s, genuinely hermetic (a guard traps any attempted `fetch`, DNS lookup or socket connect; eight tests were silently hitting the network).
- **CI from zero** — the repo had no workflows at all. Now typecheck + test on push and PR, actions pinned to commit SHAs, Dependabot.
- Mutation-tested twice. First pass: **10 of 34 mutations survived** — four security-header checks could be silently *disabled outright* with the suite still green. All closed.
- Auth-gate detection (compares registrable domains via the Public Suffix List — an earlier version refused healthy apex→www redirects and would have red-built every project doing one).
- Retry policy: skip / retry / error, classified on **stderr only** (stdout is the tool's data channel — a *successful* scan whose findings text mentioned "connection reset" was being re-run from scratch).
- osv-scanner now scans Ruby deps (`Gemfile.lock`) — it never did, and the run passed anyway.

**Decide first: rebase your work on PR #3, or restructure and let it land underneath you.** Don't silently discard it; the regression tests are the spec for what must keep working.

---

## 5. Rules for this work

- **Do not patch a seventh bug and call it done.** If you find one, note it — then fix the cause.
- **Every claim needs evidence.** Not "I fixed it" — the before/after output. This tool's entire failure was claiming things it hadn't verified; do not repeat that in the fixing of it.
- **Mutation-test your own work.** Break the code deliberately; if no test fails, your test is decoration. This suite had 10 survivors on its first pass.
- **Adversarial review before merge.** Every round found something. Assume yours will too.
- Worktree + branch + PR. Never commit on `main`. Never merge without the operator.

---

## 6. Why it matters

**42L-949** will make LGTM the mandatory CI gate for **every 42labs project**.

A scanner that invents findings burns trust — people learn to ignore it. A scanner that **hides** findings is worse: it manufactures confidence, and the investigation stops. Every one of the six bugs above was the second kind.

Related: **42L-999** — no repo in the fleet currently blocks a red build (`LGTM`, `design-system` and `42labs.io` have no branch protection at all; `tron` has protection with zero required status checks). Until that lands, any gate is advisory.

---

*Written 2026-07-14 after six review rounds on 42L-973. Context: `~/42labs/lgtm/.sweep/PLAN.md`, and the session logs in `tron-meta/logs/flynn/`.*
