import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { derive } from "../../src/scoring.js";
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
  /**
   * Make page.goto() REJECT, the way a real one does on a timeout, a redirect
   * loop, or a connection reset — all routine when a WAF decides it doesn't
   * like the scanner. Without this the suite could not see the runner's
   * nav-failure path at all, which is precisely how authz.ts came to claim
   * "protected routes enforce auth" about routes it never managed to load.
   */
  throws?: string;
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
          if (nav.throws) throw new Error(nav.throws);
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
    const r = await derive(authzRunner, ctx(["/dashboard"], null));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/no authenticated session/i);
  });

  it("skips visibly when the storageState file is missing from disk", async () => {
    const r = await derive(authzRunner, ctx(["/dashboard"], join(dir, "nope.json")));
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/storageState file missing/i);
  });
});

describe("authz.ts — anonymous access to protected routes (OWASP A01)", () => {
  const dash = "https://example.com/dashboard";

  it("flags HIGH when a protected route serves 200 anonymously with no login redirect", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 200 }; // wide open
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    const f = r.findings.find((x) => x.id === `authz-open-${dash}`)!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("high");
    expect(f.standard).toMatch(/A01/);
  });

  it("does NOT flag when anonymous access is refused with 401", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });

  it("does NOT flag when anonymous access is refused with 403", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 403 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });

  it("does NOT flag when anonymous access is redirected to a login page (LOGIN_HINT)", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: "https://example.com/login?next=/dashboard", status: 200 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
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
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-open-"))).toBeUndefined();
  });
});

describe("authz.ts — authed-session health and response cacheability", () => {
  const dash = "https://example.com/dashboard";

  it("flags a cacheable authenticated response (no no-store)", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "max-age=3600" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    const f = r.findings.find((x) => x.id === `authz-cache-${dash}`)!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("low");
    expect(f.standard).toMatch(/8\.3\.4/);
  });

  it("flags an authed response with NO cache-control header at all", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: {} };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id === `authz-cache-${dash}`)!.title).toMatch(/unset/);
  });

  it("does NOT flag cacheability when the authed response sends no-store", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id.startsWith("authz-cache-"))).toBeUndefined();
  });

  it("reports an expired/invalid session (authed context bounced to login) as info, and marks the run unreliable", async () => {
    // The session itself is dead — the access-control conclusions can't be
    // trusted, and the runner must SAY so rather than quietly reporting clean.
    authedNav[dash] = { landed: "https://example.com/login", status: 200 };
    anonNav[dash] = { landed: "https://example.com/login", status: 200 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.findings.find((x) => x.id === "authz-session-bounce")).toBeDefined();
    expect(r.findings.find((x) => x.id === "authz-session-dead")).toBeDefined();
    expect(r.meta?.sessionWorks).toBe(false);
  });

  it("refuses when no protected routes are configured — probing nothing proves nothing", async () => {
    // The old runner emitted an info note and then went on to declare
    // "Protected routes enforce auth" — a claim about routes, on a run that
    // probed none. There is no evidence here, so there is no verdict.
    const r = await derive(authzRunner, ctx([]));
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/no protected routes are configured/i);
    expect(r.coverage?.data.routesProbed).toBe(0);
  });

  it("reports a healthy, properly-guarded app as clean, with the routes it probed on record", async () => {
    authedNav[dash] = { landed: dash, status: 200, headers: { "cache-control": "no-store" } };
    anonNav[dash] = { landed: dash, status: 401 };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.status).toBe("ok");
    expect(r.findings.filter((f) => f.severity !== "info")).toEqual([]);
    expect(r.coverage?.data.routesProbed).toBe(1);
    expect(r.coverage?.data.probesFailed).toBe(0);
    expect(r.meta?.sessionWorks).toBe(true);
  });
});


// ── The nav-failure hole (42L-973 final review) ─────────────────────────────
//
// Both goto() calls used to sit in `try { … } catch { /* non-fatal */ }`. If a
// navigation blew up — timeout, redirect loop, connection reset, all realistic
// against a live WAF — the route produced NO finding: not open, not blocked,
// not even a note. And then, if nothing else was wrong, `authz-ok` fired
// anyway: "Protected routes enforce auth."
//
// That is a definite claim about a route that was never checked, inside the one
// runner whose entire job is catching broken access control. Unchecked is not
// safe; it is unknown, and unknown has to fail the run.

describe("authzRunner — a route that could not be loaded was NOT verified", () => {
  it("never reports clean when the anonymous probe failed to load the route", async () => {
    anonNav = {
      "https://example.com/dashboard": {
        landed: "",
        status: 0,
        throws: "page.goto: Timeout 30000ms exceeded",
      },
    };
    const r = await derive(authzRunner, ctx(["/dashboard"]));

    // The bug: this used to be "ok" + a self-declared pass-note, i.e. a clean
    // bill of health for a route nobody managed to load.
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/never landed/i);
    expect(r.note).toMatch(/not verified/i);
    // And the route it could not check is still named in the findings.
    expect(
      r.findings.find((f) => f.id.startsWith("authz-unchecked")),
    ).toBeDefined();
  });

  it("emits a visible, reviewable finding naming the route it could not check", async () => {
    anonNav = {
      "https://example.com/dashboard": {
        landed: "",
        status: 0,
        throws: "net::ERR_CONNECTION_RESET",
      },
    };
    const r = await derive(authzRunner, ctx(["/dashboard"]));

    const unchecked = r.findings.find((f) => f.id.startsWith("authz-unchecked"))!;
    expect(unchecked).toBeDefined();
    expect(unchecked.needsReview).toBe(true); // visible, never silently dropped
    expect(unchecked.title).toMatch(/NOT verified/);
    expect(unchecked.title).toMatch(/dashboard/);
    expect(unchecked.location).toBe("https://example.com/dashboard");
  });

  it("also refuses when it is the AUTHED probe that failed to load", async () => {
    authedNav = {
      "https://example.com/dashboard": {
        landed: "",
        status: 0,
        throws: "page.goto: Timeout 30000ms exceeded",
      },
    };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.status).toBe("error");
    expect(r.status).toBe("error");
  });

  it("still reports a genuinely open route found alongside one it could not check — a nav failure removes certainty, it does not erase evidence", async () => {
    anonNav = {
      // Wide open: anonymous 200, no login redirect. Must survive.
      "https://example.com/admin": { landed: "https://example.com/admin", status: 200 },
      // Unreachable: unknown.
      "https://example.com/billing": { landed: "", status: 0, throws: "Timeout" },
    };
    const r = await derive(authzRunner, ctx(["/admin", "/billing"]));

    const open = r.findings.find((f) => f.id.startsWith("authz-open"))!;
    expect(open).toBeDefined();
    expect(open.severity).toBe("high"); // the A01 finding is not lost
    expect(r.findings.some((f) => f.id.startsWith("authz-unchecked"))).toBe(true);
    expect(r.status).toBe("error");
  });

  it("only counts the routes it actually failed on — a fully clean run is still clean", async () => {
    // Authed request lands fine and is non-cacheable; anonymous request is
    // bounced to login. Nothing failed to load, so nothing is unverified.
    authedNav = {
      "https://example.com/dashboard": {
        landed: "https://example.com/dashboard",
        status: 200,
        headers: { "cache-control": "no-store" },
      },
    };
    anonNav = {
      "https://example.com/dashboard": {
        landed: "https://example.com/login",
        status: 200,
      },
    };
    const r = await derive(authzRunner, ctx(["/dashboard"]));
    expect(r.status).toBe("ok");
    expect(r.coverage?.data.probesFailed).toBe(0);
    expect(r.findings.some((f) => f.id.startsWith("authz-unchecked"))).toBe(false);
  });
});
