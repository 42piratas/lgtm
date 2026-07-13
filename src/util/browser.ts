import { chromium, type Browser, type BrowserContext } from "playwright";
import { existsSync } from "node:fs";
import type { SiteConfig } from "../types.js";

/**
 * A shared Chromium instance for the browser-driven runners (a11y, cookies,
 * authz). Auth is applied once via Playwright storageState so every runner
 * sees the real, logged-in app.
 */
export class BrowserSession {
  private browser?: Browser;
  private ctx?: BrowserContext;

  constructor(private readonly site: SiteConfig) {}

  async context(): Promise<BrowserContext> {
    if (this.ctx) return this.ctx;
    this.browser = await chromium.launch({ headless: true });
    const storageState =
      this.site.auth.type === "storageState" && existsSync(this.site.auth.path)
        ? this.site.auth.path
        : undefined;
    this.ctx = await this.browser.newContext({
      storageState,
      ignoreHTTPSErrors: true,
      userAgent: "lgtm/0.1 (+security-harness)",
      // Ask for reduced motion. Two reasons, and both are load-bearing:
      //
      // 1. Correctness. Well-built entrance animations skip their hidden start
      //    state entirely under `prefers-reduced-motion` (42labs.io's own
      //    RevealOnScroll does exactly this). Without it, the scan races the
      //    animation: content is still `opacity: 0`, axe treats it as not
      //    rendered, and the page comes back "clean" having audited nothing.
      //    With it, the same page deterministically exposes its real content.
      //
      // 2. It is the honest thing to audit. A reduced-motion user is a real
      //    user, and it is the render path least likely to have been looked at.
      reducedMotion: "reduce",
    });
    return this.ctx;
  }

  /** True when auth was requested but the storageState file is missing. */
  authRequestedButMissing(): boolean {
    return (
      this.site.auth.type === "storageState" && !existsSync(this.site.auth.path)
    );
  }

  async close() {
    await this.ctx?.close().catch(() => {});
    await this.browser?.close().catch(() => {});
    this.ctx = undefined;
    this.browser = undefined;
  }
}
