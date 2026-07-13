import { describe, it, expect, vi, beforeEach } from "vitest";
import type { RunnerContext, SiteConfig } from "../../src/types.js";
import type { FetchedResponse } from "../../src/util/http.js";

// headers.ts's CHECKS[] is the pure logic behind "what counts as a good
// security header". We drive it end-to-end through the real headersRunner
// by mocking only fetchUrl (isLocalhostUrl/hostOf stay real), so this tests
// the actual evaluate() functions, not a restatement of them. No file under
// src/runners/ is touched.

vi.mock("../../src/util/http.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/util/http.js")>();
  return { ...actual, fetchUrl: vi.fn() };
});

const { fetchUrl } = await import("../../src/util/http.js");
const { headersRunner } = await import("../../src/runners/headers.js");

function response(overrides: Partial<FetchedResponse> = {}): FetchedResponse {
  return {
    url: "https://example.com",
    finalUrl: "https://example.com",
    status: 200,
    headers: {},
    setCookie: [],
    body: "",
    redirected: false,
    ...overrides,
  };
}

function ctx(baseUrl: string): RunnerContext {
  const site: SiteConfig = {
    name: "site",
    baseUrl,
    routes: [],
    auth: { type: "none" },
    failOn: "high",
  };
  return {
    site,
    run: { baseUrl, isLocalhost: false, allowActive: false, outDir: "", stamp: "" },
    urls: [baseUrl],
    caps: { docker: false, browser: true },
    log: () => {},
  };
}

const STRONG_HEADERS = {
  "content-security-policy": "default-src 'self'",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=()",
  "cross-origin-opener-policy": "same-origin",
};

beforeEach(() => {
  vi.mocked(fetchUrl).mockReset();
});

describe("headersRunner — strong config passes clean", () => {
  it("reports a single info finding when every header is present and strong", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers: STRONG_HEADERS }));
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.status).toBe("ok");
    expect(result.findings).toEqual([
      expect.objectContaining({ id: "headers-ok", severity: "info" }),
    ]);
  });
});

describe("headersRunner — CSP", () => {
  it("flags 'unsafe-inline' in the CSP by name", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    const csp = result.findings.find((f) => f.id === "csp")!;
    expect(csp.severity).toBe("high");
    expect(csp.title).toMatch(/unsafe-inline/);
  });

  it("flags 'unsafe-eval' in the CSP", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; script-src 'unsafe-eval'" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "csp")!.title).toMatch(/unsafe-eval/);
  });

  it("flags a missing CSP header entirely", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["content-security-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    const csp = result.findings.find((f) => f.id === "csp")!;
    expect(csp.severity).toBe("high");
    expect(csp.title).toMatch(/no Content-Security-Policy/);
  });

  it("flags a wildcard script-src", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; script-src *" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "csp")!.title).toMatch(/wildcard/);
  });
});

describe("headersRunner — HSTS", () => {
  it("flags a missing HSTS header on an https, non-local target", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["strict-transport-security"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    const hsts = result.findings.find((f) => f.id === "hsts")!;
    expect(hsts.severity).toBe("high");
    expect(hsts.title).toMatch(/no Strict-Transport-Security/);
  });

  it("flags a max-age one second below the one-year threshold, and accepts one exactly at it", async () => {
    // The boundary itself, not a value 350x away from it: max-age=3600 would
    // still "pass" a threshold weakened to a single day. 31536000 is one year;
    // the check is `< 31536000`, so 31535999 must fail and 31536000 must not.
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "strict-transport-security": "max-age=31535999" } }),
    );
    const justUnder = await headersRunner.run(ctx("https://example.com"));
    expect(justUnder.findings.find((f) => f.id === "hsts")!.title).toMatch(
      /max-age 31535999 < 1 year/,
    );

    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "strict-transport-security": "max-age=31536000" } }),
    );
    const exactlyAt = await headersRunner.run(ctx("https://example.com"));
    expect(exactlyAt.findings.find((f) => f.id === "hsts")).toBeUndefined();
  });

  it("flags an HSTS header with no max-age directive at all", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "strict-transport-security": "includeSubDomains" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "hsts")!.title).toMatch(/no max-age directive/);
  });

  it("does not require HSTS over plain http (it is meaningless there)", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["strict-transport-security"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ url: "http://example.com", finalUrl: "http://example.com", headers }));
    const result = await headersRunner.run(ctx("http://example.com"));
    expect(result.findings.find((f) => f.id === "hsts")).toBeUndefined();
  });
});

describe("headersRunner — X-Frame-Options / frame-ancestors", () => {
  it("flags a weak X-Frame-Options value", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "x-frame-options": "ALLOW-FROM https://evil.example" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "x-frame-options")!.title).toMatch(/weak value/);
  });

  it("does not flag a missing X-Frame-Options when CSP already sets frame-ancestors", async () => {
    const headers = { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; frame-ancestors 'none'" };
    delete (headers as Record<string, string>)["x-frame-options"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "x-frame-options")).toBeUndefined();
  });
});

// The four checks below are the ones most likely to be quietly neutered: they
// are simple presence/value checks, so an `evaluate` accidentally reduced to
// `() => null` disables them forever without anything else breaking. Each is
// pinned on BOTH the missing case and the declared severity, so silently
// disabling the check — or downgrading it — fails the suite.
describe("headersRunner — x-content-type-options", () => {
  it("flags a missing header at medium severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["x-content-type-options"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "x-content-type-options")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("medium");
    expect(f.title).toMatch(/missing or not 'nosniff'/);
  });

  it("flags a present-but-wrong value (anything that isn't nosniff)", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "x-content-type-options": "sniff" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "x-content-type-options")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("medium");
  });

  it("accepts nosniff", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "x-content-type-options": "nosniff" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "x-content-type-options")).toBeUndefined();
  });
});

describe("headersRunner — referrer-policy", () => {
  it("flags a missing header at low severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["referrer-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "referrer-policy")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.title).toMatch(/no Referrer-Policy header/);
  });

  it("accepts any present value", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "referrer-policy": "no-referrer" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "referrer-policy")).toBeUndefined();
  });
});

describe("headersRunner — permissions-policy", () => {
  it("flags a missing header at low severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["permissions-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "permissions-policy")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.title).toMatch(/no Permissions-Policy header/);
  });

  it("accepts any present value", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "permissions-policy": "camera=()" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "permissions-policy")).toBeUndefined();
  });
});

describe("headersRunner — cross-origin-opener-policy", () => {
  it("flags a missing header at low severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["cross-origin-opener-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await headersRunner.run(ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "coop")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.title).toMatch(/missing\/weak COOP/);
  });

  it("flags a present-but-weak value (unsafe-none)", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "cross-origin-opener-policy": "unsafe-none" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "coop")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
  });

  it("accepts same-origin", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "cross-origin-opener-policy": "same-origin" } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "coop")).toBeUndefined();
  });
});

describe("headersRunner — information leakage", () => {
  // Every entry in LEAKY, not just the first: dropping any one of them from
  // the list must fail the suite.
  it.each([
    ["server", "nginx/1.18.0 (Ubuntu)"],
    ["x-powered-by", "Express"],
    ["x-aspnet-version", "4.0.30319"],
  ])("flags the %s header as a low-severity stack leak", async (header, value) => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, [header]: value } }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    const leak = result.findings.find((f) => f.id === `leak-${header}`)!;
    expect(leak).toBeDefined();
    expect(leak.severity).toBe("low");
    expect(leak.evidence).toContain(value);
  });

  it("flags every leaky header present, not just the first one found", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({
        headers: { ...STRONG_HEADERS, server: "nginx", "x-powered-by": "Express" },
      }),
    );
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.findings.filter((f) => f.id.startsWith("leak-"))).toHaveLength(2);
  });
});

describe("headersRunner — plaintext transport", () => {
  it("flags http:// on a non-local target as its own high finding", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ url: "http://example.com", finalUrl: "http://example.com", headers: {} }));
    const result = await headersRunner.run(ctx("http://example.com"));
    const noTls = result.findings.find((f) => f.id === "no-tls")!;
    expect(noTls.severity).toBe("high");
  });

  it("does not flag http:// on localhost", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ url: "http://localhost:3000", finalUrl: "http://localhost:3000", headers: {} }));
    const result = await headersRunner.run(ctx("http://localhost:3000"));
    expect(result.findings.find((f) => f.id === "no-tls")).toBeUndefined();
  });
});

describe("headersRunner — fetch failure", () => {
  it("reports status: error rather than throwing when the fetch itself fails", async () => {
    vi.mocked(fetchUrl).mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await headersRunner.run(ctx("https://example.com"));
    expect(result.status).toBe("error");
    expect(result.note).toMatch(/ECONNREFUSED/);
    expect(result.findings).toEqual([]);
  });
});

describe("headersRunner — regression guards for known field bugs (42L-973)", () => {
  // Live bug #4: a 429 (rate-limited) response from a WAF/CDN was reported
  // as "no security headers" — indistinguishable from the real site having
  // none. headers.ts currently evaluates whatever headers came back
  // regardless of `res.status`, so this is CURRENTLY BROKEN. Fixing it is a
  // src/runners/headers.ts behavior change, which is explicitly out of scope
  // for this PR (owned by the concurrent runner-bugs branch: "429 handling").
  // Left skipped and documented rather than faked green or fixed here.
  it.skip("does not report missing-header findings when the response itself is 429/503 (rate-limited/unavailable) — needs the runner-bugs branch's 429 handling", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ status: 429, headers: {} }));
    const result = await headersRunner.run(ctx("https://example.com"));
    // Desired post-fix behavior: an inconclusive/rate-limited signal, not a
    // wall of "missing header" findings scored against a page that was never
    // actually served.
    expect(result.findings.some((f) => /rate.?limit|429/i.test(f.title))).toBe(true);
    expect(result.findings.find((f) => f.id === "csp")).toBeUndefined();
  });

  // Live bug #3: fetchUrl follows redirects (redirect: "follow") with no
  // check that the final host still matches the target — a 302 into an
  // auth gate (e.g. Cloudflare Access) gets scored as if it were the site.
  // `finalUrl` is recorded in findings' `location`, but nothing flags the
  // host mismatch. Same story: a src/runners/headers.ts (or util/http.ts)
  // behavior change, owned by the concurrent branch ("auth-gate detection").
  it.skip("flags when the final URL redirected to a different host than requested — needs the runner-bugs branch's auth-gate detection", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({
        url: "https://app.example.com/dashboard",
        finalUrl: "https://example.cloudflareaccess.com/cdn-cgi/access/login",
        redirected: true,
        headers: STRONG_HEADERS,
      }),
    );
    const result = await headersRunner.run(ctx("https://app.example.com/dashboard"));
    expect(result.findings.some((f) => /redirect|auth.?gate|different host/i.test(f.title))).toBe(true);
  });
});
