import { describe, it, expect } from "vitest";
import { detectAuthGate, badStatusReason } from "../../src/util/authgate.js";

// 42L-973 #1/#2 and the adversarial-review follow-up.
//
// This module decides whether a black-box runner is allowed to say ANYTHING
// about a target. Two ways to get it wrong, and they fail in opposite
// directions:
//
//   too lax    → we grade Cloudflare's login page and call it the design
//                system (the original bug: ds.42labs.io got a letter grade
//                and a findings list, all about someone else's HTML).
//   too strict → every project that redirects apex→www gets a red build from
//                all five black-box runners. A gate that cries wolf gets
//                switched off, and then it protects nothing.
//
// Both directions are pinned here, deliberately and explicitly.

describe("detectAuthGate — same-site redirects are NOT gates", () => {
  it("allows apex → www (the single most common redirect on the web)", () => {
    const r = detectAuthGate("https://google.com", "https://www.google.com/");
    expect(r.gated).toBe(false);
  });

  it("allows www → apex", () => {
    expect(detectAuthGate("https://www.example.com", "https://example.com/").gated).toBe(false);
  });

  it("allows a bare http → https upgrade", () => {
    expect(detectAuthGate("http://example.com", "https://example.com/").gated).toBe(false);
  });

  it("allows any other same-registrable-domain subdomain hop", () => {
    expect(detectAuthGate("https://example.com", "https://app.example.com/x").gated).toBe(false);
  });

  it("handles a multi-label public suffix correctly (foo.co.uk is the site, co.uk is not)", () => {
    // A naive "same last two labels" rule reads both of these as `co.uk` and
    // would wave through a redirect to a COMPLETELY different company. The
    // real public suffix list gets this right.
    expect(detectAuthGate("https://foo.co.uk", "https://www.foo.co.uk").gated).toBe(false);
    expect(detectAuthGate("https://foo.co.uk", "https://evil.co.uk").gated).toBe(true);
  });

  it("allows an identical host (no redirect at all)", () => {
    expect(detectAuthGate("https://example.com/a", "https://example.com/a").gated).toBe(false);
  });

  it("allows localhost → localhost (dev servers have no registrable domain)", () => {
    expect(detectAuthGate("http://localhost:3000", "http://localhost:3000/").gated).toBe(false);
  });
});

describe("detectAuthGate — real gates and cross-site landings ARE refused", () => {
  it("refuses Cloudflare Access (the ds.42labs.io bug)", () => {
    const r = detectAuthGate(
      "https://ds.42labs.io",
      "https://labs42.cloudflareaccess.com/cdn-cgi/access/login/ds.42labs.io",
    );
    expect(r.gated).toBe(true);
    expect(r.reason).toMatch(/known auth gate/);
    expect(r.reason).toMatch(/cloudflareaccess\.com/);
  });

  it.each([
    ["Vercel SSO", "https://vercel.com/sso-api?url=x"],
    ["Okta", "https://acme.okta.com/login"],
    ["Okta EMEA", "https://acme.okta-emea.com/login"],
    ["Auth0", "https://tenant.auth0.com/login"],
  ])("refuses %s", (_name, finalUrl) => {
    const r = detectAuthGate("https://app.example.com", finalUrl);
    expect(r.gated).toBe(true);
    expect(r.reason).toMatch(/known auth gate/);
  });

  it("refuses a landing on a genuinely different site", () => {
    const r = detectAuthGate("https://example.com", "https://somewhere-else.net/login");
    expect(r.gated).toBe(true);
    expect(r.reason).toMatch(/different site/);
  });

  it("refuses a known gate even when it shares nothing else — the provider list is a hard signal", () => {
    // Checked BEFORE the same-site shortcut, so a gate is never waved through
    // on a domain technicality.
    const r = detectAuthGate("https://cloudflareaccess.com", "https://x.cloudflareaccess.com/login");
    expect(r.gated).toBe(true);
  });
});

describe("badStatusReason — absence of evidence is not evidence of absence", () => {
  it.each([200, 204, 301, 302, 399])("accepts %i", (status) => {
    expect(badStatusReason(status)).toBeNull();
  });

  it.each([429, 403, 500, 503, 404])("refuses %i with an explicit 'unknown, not absent'", (status) => {
    const reason = badStatusReason(status)!;
    expect(reason).toMatch(new RegExp(String(status)));
    expect(reason).toMatch(/unknown, not absent/i);
  });
});
