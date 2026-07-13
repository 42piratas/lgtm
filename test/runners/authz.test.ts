import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// authz.ts is the broken-access-control smoke test — the runner that emits the
// single highest-consequence finding in the whole tool ("protected route
// reachable anonymously", OWASP A01, severity high). It had no tests at all.
//
// The logic under test is LOGIN_HINT (what counts as "bounced to login"), the
// anonymous-access verdict (blocked vs. open), and authed-response
// cacheability. We mock playwright's chromium and drive the real runner.

interface FakeNav {
  /** Where the browser ended up (page.url()) after the nav. */
  landed: string;
  status: number;
  headers?: Record<string, string>;
}

// url → what the authed context sees / what the anonymous context sees.
let authedNav: Record<string, FakeNav> = {};
let anonNav: Record<string, FakeNav> = {};

function makeContext(navMap: Record<string, FakeNav>) {
  return {
    newPage: async () => {
      let current = "";
      return {
        goto: async (url: string) => {
          const nav = navMap[url] ?? { landed: url, status: 200, headers: {} };
          current = nav.landed;
          return {
            status: () => nav.status,
            headers: () => nav.headers ?? {},
          };
        },
        url: () => current,
        close: async () => {},
      };
    },
  };
}

vi.mock("playwright", () => ({
  chromium: {
    launch: async () => ({
      newContext: async (opts?: { storageState?: string }) =>
        makeContext(opts?.storageState ? authedNav : anonNav),
      close: async () => {},
    }),
  },
}));

const { authzRunner } = await import("../../src/runners/authz.js");

let dir: string;
let statePath: string;

beforeEach(() => {
  authedNav = {};
  anonNav = {};
  dir = mkdtempSync(join(tmpdir(), "lgtm-authz-"));
  statePath = join(dir, "state.json");
  writeFileSync(statePath, JSON.stringify({ cookies: [], origins: [] }));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function ctx(routes: string[], authPath: string | null = statePath): RunnerContext {
  const baseUrl = "https://example.com";
  const site: SiteConfig = {
    name: "site",
    baseUrl,
    routes,
    auth: authPath ? { type: "storageState", path: authPath } : { type: "none" },
    failOn: "high",
  };
  return {
    site,
    run: { baseUrl, isLocalhost: false, allowActive: false, outDir: "", stamp: "" },
    urls: [baseUrl, ...routes.map((r) => new URL(r, baseUrl).toString())],
    caps: { docker: false, browser: true },
    log: () => {},
  };
}

describe("authz.ts — preconditions", () => {
  it("skips visibly when the site has no authenticated session configured", async () => {
    const r = await authzRunner.run(ctx(["/dashboard"], null));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/no authenticated session/i);
  });

  it("skips visibly when the storageState file is missing from disk", async () => {
    const r = await authzRunner.run(ctx(["/dashboard"], join(dir, "nope.json")));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/storageState file missing/i);
  });
});

describe("authz.ts — anonymous access to protected routes (OWASP A01)", () => {
  const dash = "https://example.com/dashboard";

  it("flags HIGH when a protected route serves 200 anonymously with no login redirect", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 200 }; // wide open
    const r = await authzRunner.run(ctx(["/dashboard"]));
    const f = r.findings.find((x) => x.id === `authz-open-${dash}`)!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("high");
    expect(f.standard).toMatch(/A01/);
  });

  it("does NOT flag when anonymous access is refused with 401", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });

  it("does NOT flag when anonymous access is refused with 403", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 403 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });

  it("does NOT flag when anonymous access is redirected to a login page (LOGIN_HINT)", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: "https://example.com/login?next=/dashboard", status: 200 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });

  it.each([
    ["https://example.com/login", "login"],
    ["https://example.com/signin", "signin"],
    ["https://example.com/sign-in", "sign-in"],
    ["https://example.com/auth/start", "auth"],
    ["https://example.com/authenticate", "/authenticate"],
  ])("treats a redirect to %s as a login bounce (LOGIN_HINT covers %s)", async (landed) => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed, status: 200 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });
});

describe("authz.ts — authed-session health and response cacheability", () => {
  const dash = "https://example.com/dashboard";

  it("flags a cacheable authenticated response (no no-store)", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "max-age=3600" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    const f = r.findings.find((x) => x.id === `authz-cache-${dash}`)!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.standard).toMatch(/8\.3\.4/);
  });

  it("flags an authed response with NO cache-control header at all", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: {} };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id === `authz-cache-${dash}`)!.title).toMatch(/unset/);
  });

  it("does NOT flag cacheability when the authed response sends no-store", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-cache-"))).toBeUndefined();
  });

  it("reports an expired/invalid session (authed context bounced to login) as info, and marks the run unreliable", async () => {
    // The session itself is dead — the access-control conclusions can't be
    // trusted, and the runner must SAY so rather than quietly reporting clean.
    authedNav[dash] = { landed: "https://example.com/login", status: 200 };
    anonNav[dash] = { landed: "https://example.com/login", status: 200 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id === "authz-session-bounce")).toBeDefined();
    expect(r.findings.find((x) => x.id === "authz-session-dead")).toBeDefined();
    expect(r.meta?.sessionWorks).toBe(false);
  });

  it("notes when no protected routes are configured — there is nothing to prove", async () => {
    const r = await authzRunner.run(ctx([]));
    expect(r.findings.find((x) => x.id === "authz-no-routes")).toBeDefined();
  });

  it("reports a healthy, properly-guarded app as clean", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await authzRunner.run(ctx(["/dashboard"]));
    expect(r.status).toBe("ok");
    expect(r.findings.filter((f) => f.severity !== "info")).toEqual([]);
    expect(r.findings.find((f) => f.id === "authz-ok")).toBeDefined();
    expect(r.meta?.sessionWorks).toBe(true);
  });
});
