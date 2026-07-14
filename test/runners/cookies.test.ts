import { describe, it, expect, vi, beforeEach } from "vitest";
import { derive } from "../../src/scoring.js";
import type { RunnerContext, SiteConfig } from "../../src/types.js";
import type { FetchedResponse } from "../../src/util/http.js";

vi.mock("../../src/util/http.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/util/http.js")>();
  return { ...actual, fetchUrl: vi.fn() };
});

const { fetchUrl } = await import("../../src/util/http.js");
const { cookiesRunner } = await import("../../src/runners/cookies.js");

function response(setCookie: string[], overrides: Partial<FetchedResponse> = {}): FetchedResponse {
  return {
    url: "https://example.com",
    finalUrl: "https://example.com",
    status: 200,
    headers: {},
    setCookie,
    body: "",
    redirected: false,
    ...overrides,
  };
}

function ctx(baseUrl = "https://example.com"): RunnerContext {
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

beforeEach(() => {
  vi.mocked(fetchUrl).mockReset();
});

describe("cookiesRunner", () => {
  it("flags a session cookie missing HttpOnly", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response(["sessionid=abc123; Path=/; Secure; SameSite=Lax"]));
    const result = await derive(cookiesRunner, ctx());
    const f = result.findings.find((x) => x.id === "cookie-httponly-sessionid")!;
    expect(f.severity).toBe("high");
  });

  it("flags a sensitive cookie missing Secure over https as high, a non-sensitive one as medium", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response([
        "sessionid=abc; HttpOnly; SameSite=Lax", // sensitive, no Secure
        "theme=dark; HttpOnly; SameSite=Lax", // not sensitive, no Secure
      ]),
    );
    const result = await derive(cookiesRunner, ctx());
    expect(result.findings.find((f) => f.id === "cookie-secure-sessionid")!.severity).toBe("high");
    expect(result.findings.find((f) => f.id === "cookie-secure-theme")!.severity).toBe("medium");
  });

  it("flags a missing SameSite attribute, scaled by sensitivity", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response(["sessionid=abc; HttpOnly; Secure", "theme=dark; HttpOnly; Secure"]),
    );
    const result = await derive(cookiesRunner, ctx());
    expect(result.findings.find((f) => f.id === "cookie-samesite-sessionid")!.severity).toBe("medium");
    expect(result.findings.find((f) => f.id === "cookie-samesite-theme")!.severity).toBe("low");
  });

  it("flags SameSite=None without Secure as high, regardless of sensitivity", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response(["theme=dark; HttpOnly; SameSite=None"]));
    const result = await derive(cookiesRunner, ctx());
    const f = result.findings.find((x) => x.id === "cookie-samesite-none-insecure-theme")!;
    expect(f.severity).toBe("high");
  });

  it("raises the CSRF signal when a session cookie exists with no CSRF token anywhere", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response(["sessionid=abc; HttpOnly; Secure; SameSite=Lax"]));
    const result = await derive(cookiesRunner, ctx());
    expect(result.findings.find((f) => f.id === "csrf-signal")).toBeDefined();
  });

  it("does not raise the CSRF signal when a CSRF cookie is present", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response([
        "sessionid=abc; HttpOnly; Secure; SameSite=Lax",
        "csrftoken=xyz; HttpOnly; Secure; SameSite=Strict",
      ]),
    );
    const result = await derive(cookiesRunner, ctx());
    expect(result.findings.find((f) => f.id === "csrf-signal")).toBeUndefined();
  });

  it("is clean, with the response on record, when there are no cookies at all", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(response([]));
    const result = await derive(cookiesRunner, ctx());
    // No invented pass-note. Clean = no findings, and coverage proving a
    // response was genuinely read — the difference between "this site sets no
    // cookies" and "we never saw this site".
    expect(result.findings).toEqual([]);
    expect(result.status).toBe("ok");
    expect(result.coverage?.data.responded).toBe(true);
    expect(result.coverage?.data.cookies).toBe(0);
  });

  it("is clean when every cookie is sound", async () => {
    vi.mocked(fetchUrl).mockResolvedValue(
      response([
        "sessionid=abc; HttpOnly; Secure; SameSite=Lax",
        "csrftoken=xyz; HttpOnly; Secure; SameSite=Strict",
      ]),
    );
    const result = await derive(cookiesRunner, ctx());
    expect(result.findings).toEqual([]);
    expect(result.status).toBe("ok");
    expect(result.coverage?.data.cookies).toBe(2);
  });

  it("reports status: error rather than throwing when the fetch itself fails", async () => {
    vi.mocked(fetchUrl).mockRejectedValue(new Error("timeout"));
    const result = await derive(cookiesRunner, ctx());
    expect(result.status).toBe("error");
    expect(result.note).toMatch(/timeout/);
  });
});
