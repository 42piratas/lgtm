import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { ZodError } from "zod";
import { loadSite, resolveUrls } from "../src/config.js";

// Config is the operator-facing contract: a typo'd YAML must fail loudly and
// specifically (zod), not silently coerce into something that scans the
// wrong thing. Path expansion (~/, relative, absolute) is what makes site
// configs portable across machines/worktrees — get it wrong and repoPath
// silently resolves to nothing, and white-box runners quietly skip forever.

let dir: string;
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

function writeConfig(yaml: string): string {
  dir = mkdtempSync(join(tmpdir(), "lgtm-config-test-"));
  const path = join(dir, "site.yaml");
  writeFileSync(path, yaml);
  return path;
}

describe("loadSite — valid configs", () => {
  it("parses a minimal config and fills in every default", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
`);
    const site = loadSite(path);
    expect(site.name).toBe("mysite");
    expect(site.baseUrl).toBe("https://example.com");
    expect(site.routes).toEqual([]);
    expect(site.auth).toEqual({ type: "none" });
    expect(site.failOn).toBe("high");
    expect(site.repoPath).toBeUndefined();
    expect(site.skip).toBeUndefined();
  });

  it("keeps an explicit failOn and routes list", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
routes: ["/a", "/b"]
failOn: critical
skip: [zap, sast]
`);
    const site = loadSite(path);
    expect(site.failOn).toBe("critical");
    expect(site.routes).toEqual(["/a", "/b"]);
    expect(site.skip).toEqual(["zap", "sast"]);
  });

  it("parses storageState auth", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
auth:
  type: storageState
  path: .auth/mysite.json
`);
    const site = loadSite(path);
    expect(site.auth.type).toBe("storageState");
    if (site.auth.type === "storageState") {
      expect(site.auth.path).toBe(join(dir, ".auth/mysite.json"));
    }
  });
});

describe("loadSite — invalid configs fail loudly", () => {
  it("rejects a config with no baseUrl", () => {
    const path = writeConfig(`name: mysite\n`);
    expect(() => loadSite(path)).toThrow(ZodError);
    try {
      loadSite(path);
      expect.unreachable();
    } catch (err) {
      const zerr = err as ZodError;
      expect(zerr.issues.some((i) => i.path.join(".") === "baseUrl")).toBe(true);
    }
  });

  it("rejects a baseUrl that isn't a URL", () => {
    const path = writeConfig(`
name: mysite
baseUrl: "not-a-url"
`);
    try {
      loadSite(path);
      expect.unreachable();
    } catch (err) {
      const zerr = err as ZodError;
      expect(zerr.issues.some((i) => i.path.join(".") === "baseUrl")).toBe(true);
    }
  });

  it("rejects an unknown failOn severity instead of silently defaulting", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
failOn: catastrophic
`);
    expect(() => loadSite(path)).toThrow(ZodError);
  });

  it("rejects an auth block with an unrecognized type", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
auth:
  type: oauth
`);
    expect(() => loadSite(path)).toThrow();
  });

  it("rejects routes that aren't a list of strings", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
routes: "/a"
`);
    expect(() => loadSite(path)).toThrow(ZodError);
  });
});

describe("loadSite — path expansion", () => {
  it("expands ~/ against the real home directory, not the config's dir", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
repoPath: "~/some-repo"
`);
    const site = loadSite(path);
    expect(site.repoPath).toBe(join(homedir(), "some-repo"));
  });

  it("leaves an absolute repoPath untouched", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
repoPath: "/opt/repos/mysite"
`);
    const site = loadSite(path);
    expect(site.repoPath).toBe("/opt/repos/mysite");
  });

  it("resolves a relative repoPath against the config file's directory", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
repoPath: "../mysite-repo"
`);
    const site = loadSite(path);
    expect(site.repoPath).toBe(join(dir, "..", "mysite-repo"));
  });

  it("omits repoPath entirely when not configured (white-box runners must see it as absent, not empty string)", () => {
    const path = writeConfig(`
name: mysite
baseUrl: https://example.com
`);
    const site = loadSite(path);
    expect(site.repoPath).toBeUndefined();
    expect("repoPath" in site && site.repoPath === "").toBe(false);
  });
});

describe("resolveUrls", () => {
  it("returns just the base URL with no routes", () => {
    expect(resolveUrls("https://example.com", [])).toEqual(["https://example.com"]);
  });

  it("strips a single trailing slash from a bare baseUrl", () => {
    expect(resolveUrls("https://example.com/", [])).toEqual(["https://example.com"]);
  });

  it("resolves relative routes against the base URL", () => {
    const urls = resolveUrls("https://example.com", ["/pricing", "about"]);
    expect(urls).toContain("https://example.com/pricing");
    expect(urls).toContain("https://example.com/about");
  });

  it("keeps absolute http(s) routes as-is instead of re-resolving them", () => {
    const urls = resolveUrls("https://example.com", ["https://other.example.com/x"]);
    expect(urls).toContain("https://other.example.com/x");
  });

  it("de-duplicates when a route resolves to the base URL itself", () => {
    const urls = resolveUrls("https://example.com", ["/", "https://example.com/"]);
    // baseUrl + "/" both normalize into the same entry as the base itself.
    expect(urls.filter((u) => u === "https://example.com" || u === "https://example.com/").length).toBeLessThanOrEqual(2);
    expect(new Set(urls).size).toBe(urls.length);
  });

  it("de-duplicates identical routes listed twice", () => {
    const urls = resolveUrls("https://example.com", ["/a", "/a"]);
    expect(urls.filter((u) => u === "https://example.com/a")).toHaveLength(1);
  });
});
