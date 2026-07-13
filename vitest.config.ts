import { defineConfig } from "vitest/config";

// Hermetic by design: node environment, no network/docker/browser in the
// default suite. Anything needing a live browser or Docker belongs behind a
// separate, explicitly-invoked script — not in `npm test`.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // Hard guard: any test that reaches for the network fails immediately and
    // says so, on every machine. See test/setup/no-network.ts — the CI job
    // claims to be hermetic, so the suite has to actually be hermetic.
    setupFiles: ["test/setup/no-network.ts"],
    restoreMocks: true,
    testTimeout: 5_000,
    env: {
      // Run the real retry logic, but without sleeping through the backoff.
      // A unit test that idles for 1.5s buys nothing, and — as CI proved —
      // slow tests are where real I/O hides. With this at 0, ANY test still
      // taking >50ms is doing something it shouldn't, which makes the timing
      // column a usable smoke detector instead of noise.
      LGTM_RETRY_BACKOFF_MS: "0",
    },
  },
});
