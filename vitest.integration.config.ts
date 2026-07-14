import { defineConfig } from "vitest/config";

// The OPPOSITE of the default suite, on purpose.
//
// `npm test` is hermetic: Docker is mocked out, and every scanner's output is a
// fixture. That is the right default — it is fast, deterministic, and it guards
// the parsing and the verdict logic. But it is structurally blind to one entire
// class of bug: the flags we pass the real tool being wrong.
//
// It missed exactly that. `secrets` asked gitleaks for its report on
// `--report-path /dev/stdout`. gitleaks accepts that and writes nothing to it,
// so the runner had never reported a single leaked secret — on any repo, ever —
// while every unit test passed, because every unit test handed the parser a
// report the real tool would never have delivered.
//
// A mock cannot catch a lie told to the mock. These tests speak to the actual
// container images: real gitleaks, real osv-scanner, real semgrep, against real
// repositories with real planted secrets. They are slow and they need Docker,
// so they are not in `npm test` — but they run in CI, because the one thing this
// tool must never do is report a clean bill of health for a scan that never
// looked.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/integration/**/*.test.ts"],
    restoreMocks: true,
    // Pulling and running scanner images is minutes, not milliseconds.
    testTimeout: 300_000,
    hookTimeout: 300_000,
    // Docker on one socket; parallel image pulls thrash it.
    fileParallelism: false,
  },
});
