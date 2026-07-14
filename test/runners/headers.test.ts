import { describe, it, expect, vi, beforeEach } from "vitest";
import { derive } from "../../src/scoring.js";
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
  it("is clean, with the response and check count on record, when every header is present and strong", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers: STRONG_HEADERS }));
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.status).toBe("ok");
    expect(result.findings).toEqual([]);
    expect(result.coverage?.data.responded).toBe(true);
    expect(Number(result.coverage?.data.checksEvaluated)).toBeGreaterThan(0);
  });
});

describe("headersRunner — CSP", () => {
  it("flags 'unsafe-inline' in the CSP by name", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    const csp = result.findings.find((f) => f.id === "csp")!;
    expect(csp.severity).toBe("high");
    expect(csp.title).toMatch(/unsafe-inline/);
  });

  it("flags 'unsafe-eval' in the CSP", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; script-src 'unsafe-eval'" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "csp")!.title).toMatch(/unsafe-eval/);
  });

  it("flags a missing CSP header entirely", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["content-security-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await derive(headersRunner, ctx("https://example.com"));
    const csp = result.findings.find((f) => f.id === "csp")!;
    expect(csp.severity).toBe("high");
    expect(csp.title).toMatch(/no Content-Security-Policy/);
  });

  it("flags a wildcard script-src", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; script-src *" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "csp")!.title).toMatch(/wildcard/);
  });
});

describe("headersRunner — HSTS", () => {
  it("flags a missing HSTS header on an https, non-local target", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["strict-transport-security"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await derive(headersRunner, ctx("https://example.com"));
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
    const justUnder = await derive(headersRunner, ctx("https://example.com"));
    expect(justUnder.findings.find((f) => f.id === "hsts")!.title).toMatch(
      /max-age 31535999 < 1 year/,
    );

    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "strict-transport-security": "max-age=31536000" } }),
    );
    const exactlyAt = await derive(headersRunner, ctx("https://example.com"));
    expect(exactlyAt.findings.find((f) => f.id === "hsts")).toBeUndefined();
  });

  it("flags an HSTS header with no max-age directive at all", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "strict-transport-security": "includeSubDomains" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "hsts")!.title).toMatch(/no max-age directive/);
  });

  it("does not require HSTS over plain http (it is meaningless there)", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["strict-transport-security"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ url: "http://example.com", finalUrl: "http://example.com", headers }));
    const result = await derive(headersRunner, ctx("http://example.com"));
    expect(result.findings.find((f) => f.id === "hsts")).toBeUndefined();
  });
});

describe("headersRunner — X-Frame-Options / frame-ancestors", () => {
  it("flags a weak X-Frame-Options value", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "x-frame-options": "ALLOW-FROM https://evil.example" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((f) => f.id === "x-frame-options")!.title).toMatch(/weak value/);
  });

  it("does not flag a missing X-Frame-Options when CSP already sets frame-ancestors", async () => {
    const headers = { ...STRONG_HEADERS, "content-security-policy": "default-src 'self'; frame-ancestors 'none'" };
    delete (headers as Record<string, string>)["x-frame-options"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await derive(headersRunner, ctx("https://example.com"));
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
    const result = await derive(headersRunner, ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "x-content-type-options")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("medium");
    expect(f.title).toMatch(/missing or not 'nosniff'/);
  });

  it("flags a present-but-wrong value (anything that isn't nosniff)", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "x-content-type-options": "sniff" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "x-content-type-options")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("medium");
  });

  it("accepts nosniff", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "x-content-type-options": "nosniff" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "x-content-type-options")).toBeUndefined();
  });
});

describe("headersRunner — referrer-policy", () => {
  it("flags a missing header at low severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["referrer-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await derive(headersRunner, ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "referrer-policy")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.title).toMatch(/no Referrer-Policy header/);
  });

  it("accepts any present value", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "referrer-policy": "no-referrer" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "referrer-policy")).toBeUndefined();
  });
});

describe("headersRunner — permissions-policy", () => {
  it("flags a missing header at low severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["permissions-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await derive(headersRunner, ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "permissions-policy")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.title).toMatch(/no Permissions-Policy header/);
  });

  it("accepts any present value", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "permissions-policy": "camera=()" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.find((x) => x.id === "permissions-policy")).toBeUndefined();
  });
});

describe("headersRunner — cross-origin-opener-policy", () => {
  it("flags a missing header at low severity", async () => {
    const headers = { ...STRONG_HEADERS };
    delete (headers as Record<string, string>)["cross-origin-opener-policy"];
    vi.mocked(fetchUrl).mockResolvedValue(response({ headers }));
    const result = await derive(headersRunner, ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "coop")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.title).toMatch(/missing\/weak COOP/);
  });

  it("flags a present-but-weak value (unsafe-none)", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "cross-origin-opener-policy": "unsafe-none" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
    const f = result.findings.find((x) => x.id === "coop")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
  });

  it("accepts same-origin", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({ headers: { ...STRONG_HEADERS, "cross-origin-opener-policy": "same-origin" } }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));
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
    const result = await derive(headersRunner, ctx("https://example.com"));
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
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.findings.filter((f) => f.id.startsWith("leak-"))).toHaveLength(2);
  });
});

describe("headersRunner — plaintext transport", () => {
  it("flags http:// on a non-local target as its own high finding", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ url: "http://example.com", finalUrl: "http://example.com", headers: {} }));
    const result = await derive(headersRunner, ctx("http://example.com"));
    const noTls = result.findings.find((f) => f.id === "no-tls")!;
    expect(noTls.severity).toBe("high");
  });

  it("does not flag http:// on localhost", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ url: "http://localhost:3000", finalUrl: "http://localhost:3000", headers: {} }));
    const result = await derive(headersRunner, ctx("http://localhost:3000"));
    expect(result.findings.find((f) => f.id === "no-tls")).toBeUndefined();
  });
});

describe("headersRunner — fetch failure", () => {
  it("reports status: error rather than throwing when the fetch itself fails", async () => {
    vi.mocked(fetchUrl).mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.status).toBe("error");
    expect(result.note).toMatch(/ECONNREFUSED/);
    expect(result.findings).toEqual([]);
  });
});

describe("headersRunner — regression guards for known field bugs (42L-973)", () => {
  // These two were written as `it.skip` against a *guessed* post-fix contract
  // (a finding whose title mentions 429 / the auth gate). The shipped fix uses
  // a different, better one: the runner REFUSES to score at all — status
  // "error" with the reason in `note`, and an empty findings list. Emitting a
  // "finding" would be wrong: a finding is a statement about the site, and the
  // whole point is that we never saw the site. Re-pointed at the real contract
  // rather than bent to match the guess.

  // Live bug #2: a 429 from a WAF/CDN (Vercel Bot Protection on 42labs.io) was
  // reported as "no security headers" — indistinguishable from the real site
  // having none, on a site that in a browser returns 200 with all 8.
  it("refuses to score (status error), rather than reporting missing headers, when the response is a 429", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ status: 429, headers: {} }));
    const result = await derive(headersRunner, ctx("https://example.com"));

    expect(result.status).toBe("error");
    expect(result.note).toMatch(/429/);
    expect(result.note).toMatch(/unknown, not absent/i);
    // The critical assertion: NOT a wall of "missing header" findings scored
    // against a page that was never actually served.
    expect(result.findings).toHaveLength(0);
    expect(result.findings.find((f) => f.id === "csp")).toBeUndefined();
  });

  it("refuses to score a 503 the same way — any non-2xx/3xx is 'unknown', not 'clean'", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response({ status: 503, headers: {} }));
    const result = await derive(headersRunner, ctx("https://example.com"));
    expect(result.status).toBe("error");
    expect(result.note).toMatch(/503/);
    expect(result.findings).toHaveLength(0);
  });

  // Live bug #1: fetchUrl follows redirects with no check that the final host
  // still matches the target — a 302 into Cloudflare Access got scored as if
  // it were the site (ds.42labs.io was graded on Cloudflare's login page).
  it("refuses to score when the response landed on a known auth gate instead of the target", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({
        url: "https://app.example.com/dashboard",
        finalUrl: "https://example.cloudflareaccess.com/cdn-cgi/access/login",
        redirected: true,
        headers: STRONG_HEADERS,
      }),
    );
    const result = await derive(headersRunner, ctx("https://app.example.com/dashboard"));

    expect(result.status).toBe("error");
    expect(result.note).toMatch(/auth gate/i);
    expect(result.note).toMatch(/cloudflareaccess\.com/);
    expect(result.findings).toHaveLength(0);
  });

  // The other half of that fix, and the one adversarial review caught: an
  // apex→www redirect is NOT an auth gate. If this regresses, every project
  // that redirects to www gets a red build from all five black-box runners —
  // and a gate that cries wolf gets switched off.
  it("still scores normally across an apex→www redirect — that is the same site, not a gate", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response({
        url: "https://example.com",
        finalUrl: "https://www.example.com/",
        redirected: true,
        headers: STRONG_HEADERS,
      }),
    );
    const result = await derive(headersRunner, ctx("https://example.com"));

    expect(result.status).toBe("ok");
    expect(result.note).toBeUndefined();
  });
});
