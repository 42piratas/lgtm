import { defineConfig } from "vitest/config";

// Hermetic by design: node environment, no network/docker/browser in the
// default suite. Anything needing a live browser or Docker belongs behind a
// separate, explicitly-invoked script — not in `npm test`.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    restoreMocks: true,
    testTimeout: 5_000,
  },
});
