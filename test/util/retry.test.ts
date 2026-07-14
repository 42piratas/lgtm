import { describe, it, expect, vi } from "vitest";
import { withRetry, isTransientFailure, RETRY_ATTEMPTS } from "../../src/util/retry.js";
import { transientInfraFailure, transientInfraFailureUnless } from "../../src/util/docker.js";
import type { ExecResult } from "../../src/util/exec.js";

// 42L-973 resilience policy. computePass now hard-fails a run on any runner
// error, which is correct for "the scanner could not see the site" and wrong
// for "the network hiccuped for 300ms". Failing someone's CI over a blip is
// how a gate gets disabled — and a disabled gate protects nothing. So
// transient failures get a bounded retry before anything is concluded.
//
// The other edge matters just as much: a PERMANENT failure must not be
// retried (a wrong image tag would just take 3x as long to fail), and a
// definite HTTP answer from the server (429/5xx) is never retried at all —
// that's handled by the callers, which only retry transport errors.

describe("isTransientFailure", () => {
  it.each([
    ["i/o timeout", "Error response from daemon: i/o timeout"],
    ["dial tcp", "dial tcp 1.2.3.4:443: connect: connection refused"],
    ["connection reset", "read: connection reset by peer"],
    ["TLS handshake", "net/http: TLS handshake timeout"],
    ["registry throttle", "toomanyrequests: Too Many Requests"],
    ["truncated read", "unexpected end of JSON input"],
  ])("treats %s as transient", (_label, text) => {
    expect(isTransientFailure(text)).toBe(true);
  });

  it.each([
    ["a wrong image tag", "manifest for foo:nope not found: manifest unknown"],
    ["a bad CLI flag", "semgrep scan: unknown option '--nope'"],
    ["a plain nonzero exit", "exited with code 1"],
  ])("does NOT treat %s as transient — retrying a permanent failure just wastes time", (_l, text) => {
    expect(isTransientFailure(text)).toBe(false);
  });
});

describe("withRetry", () => {
  it("returns immediately, without retrying, when the first attempt succeeds", async () => {
    const fn = vi.fn().mockResolvedValue({ ok: true });
    const out = await withRetry(fn, (r: { ok: boolean }) => !r.ok);
    expect(out).toEqual({ ok: true });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries a transient failure and returns the eventual success", async () => {
    const fn = vi
      .fn()
      .mockResolvedValueOnce({ ok: false })
      .mockResolvedValueOnce({ ok: true });
    const out = await withRetry(fn, (r: { ok: boolean }) => !r.ok);
    expect(out).toEqual({ ok: true });
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("gives up after a bounded number of attempts and returns the last failure — it never loops forever", async () => {
    const fn = vi.fn().mockResolvedValue({ ok: false });
    const out = await withRetry(fn, (r: { ok: boolean }) => !r.ok);
    expect(out).toEqual({ ok: false });
    // 1 initial attempt + RETRY_ATTEMPTS retries, and not one more.
    expect(fn).toHaveBeenCalledTimes(1 + RETRY_ATTEMPTS);
  });

  it("does not retry a failure the predicate calls permanent", async () => {
    const fn = vi.fn().mockResolvedValue({ ok: false, permanent: true });
    const out = await withRetry(fn, (r: { permanent?: boolean }) => !r.permanent);
    expect(out).toEqual({ ok: false, permanent: true });
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

// ── Per-tool retry classification (42L-973 final review) ────────────────────
//
// The shared predicate used to be `code !== 0 && isTransientFailure(stderr ||
// stdout)`. Two things were wrong with that, and together they meant a
// SUCCESSFUL scan could be thrown away and re-run from scratch:
//
//   1. A nonzero exit is these tools' normal "I found problems" signal —
//      osv-scanner exits 1 when it finds vulnerabilities, ZAP when it finds
//      alerts, semgrep when it finds matches.
//   2. It fell through to STDOUT, which is the tool's DATA channel. A real CVE
//      summary mentioning "net/http", or a ZAP alert reporting a genuine 500 it
//      deliberately elicited, matched the transient patterns.
//
// For ZAP that is up to 20 minutes of re-scanning to arrive at the same answer.
// The predicate is now per-tool: stderr only, and file-output runners also check
// whether the report was actually written.

describe("transientInfraFailure — never retry a tool that worked", () => {
  const R = (o: Partial<ExecResult>): ExecResult => ({
    code: 0,
    stdout: "",
    stderr: "",
    timedOut: false,
    ...o,
  });

  it("does NOT retry osv-scanner exiting 1 with vulns found, even when a CVE summary says 'net/http'", () => {
    expect(
      transientInfraFailure(
        R({ code: 1, stdout: '{"results":[{"summary":"DoS in net/http handler"}]}' }),
      ),
    ).toBe(false);
  });

  it("does NOT retry semgrep exiting 1 with findings whose text mentions 'connection reset'", () => {
    expect(
      transientInfraFailure(
        R({ code: 1, stdout: '{"results":[{"message":"unhandled connection reset by peer"}]}' }),
      ),
    ).toBe(false);
  });

  it("does NOT retry a permanent failure (wrong image tag)", () => {
    expect(
      transientInfraFailure(R({ code: 125, stderr: "manifest unknown: manifest unknown" })),
    ).toBe(false);
  });

  it("DOES retry a genuine image-pull timeout (transient text on stderr, no output)", () => {
    expect(
      transientInfraFailure(
        R({ code: 125, stderr: "Error response from daemon: i/o timeout" }),
      ),
    ).toBe(true);
  });

  it("DOES retry a container we timed out and SIGKILLed ourselves", () => {
    expect(transientInfraFailure(R({ code: -1, timedOut: true }))).toBe(true);
  });

  // The doc comment used to claim OOM kills were retried while NOTHING matched
  // exit 137 or a bare "Killed" — it failed closed, turning a memory blip on a
  // busy runner into a hard build failure. 137 usually arrives with EMPTY
  // stderr, so it has to be matched on the code, not on text.
  it("DOES retry an OOM-killed container — exit 137 with empty stderr", () => {
    expect(transientInfraFailure(R({ code: 137, stderr: "" }))).toBe(true);
  });
});

describe("transientInfraFailureUnless — a written report means the tool answered", () => {
  const R = (o: Partial<ExecResult>): ExecResult => ({
    code: 0,
    stdout: "",
    stderr: "",
    timedOut: false,
    ...o,
  });

  it("does NOT retry ZAP when the report exists, even on a nonzero exit with a 500 in stdout", () => {
    // ZAP exits nonzero whenever it finds alerts, and an active scan exists
    // precisely to elicit 500s. Re-running here would cost ~20 minutes for the
    // identical result.
    const predicate = transientInfraFailureUnless(() => true); // report written
    expect(
      predicate(R({ code: 2, stdout: "WARN: server returned 500 Internal Server Error" })),
    ).toBe(false);
  });

  it("DOES retry when no report was written and the failure looks transient", () => {
    const predicate = transientInfraFailureUnless(() => false); // no report
    expect(predicate(R({ code: 1, stderr: "net/http: TLS handshake timeout" }))).toBe(true);
  });

  it("still does NOT retry a permanent failure even with no report written", () => {
    const predicate = transientInfraFailureUnless(() => false);
    expect(predicate(R({ code: 125, stderr: "manifest unknown" }))).toBe(false);
  });
});
