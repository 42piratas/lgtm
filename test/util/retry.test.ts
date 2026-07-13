import { describe, it, expect, vi } from "vitest";
import { withRetry, isTransientFailure, RETRY_ATTEMPTS } from "../../src/util/retry.js";

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
