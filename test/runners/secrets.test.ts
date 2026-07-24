import { describe, it, expect } from "vitest";
import { secretsRunner } from "../../src/runners/secrets.js";
import type { Coverage } from "../../src/types.js";

const CTX = {} as never;
const cov = (data: Coverage["data"]): Coverage => ({
  trail: [],
  data,
  provenance: "gitleaks scan log (stderr)",
});

// The evidence contract must still REFUSE a scan that examined nothing — but a
// diff-scoped PR scan whose base..head range is empty (0 commits) examined
// exactly what the PR introduced: nothing. That is a clean pass, not missing
// evidence. This is the fix for the intermittent false-red on rapid merges,
// where the PR range legitimately resolved to zero commits.
describe("secretsRunner.sufficient — diff-scoped empty range is a pass", () => {
  it("REFUSES an unscoped scan that walked 0 commits (non-repo / no history)", () => {
    const reason = secretsRunner.sufficient(
      cov({ commits: 0, bytes: 0, scoped: false }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/0 commits/);
  });

  it("stays strict when the scoped flag is absent (defaults to refusal)", () => {
    expect(secretsRunner.sufficient(cov({ commits: 0, bytes: 0 }), CTX)).not.toBeNull();
  });

  it("PASSES a diff-scoped scan whose PR range introduced 0 commits", () => {
    expect(
      secretsRunner.sufficient(cov({ commits: 0, bytes: 0, scoped: true }), CTX),
    ).toBeNull();
  });

  it("passes a real scan that examined commits and bytes (scoped or not)", () => {
    expect(
      secretsRunner.sufficient(cov({ commits: 14, bytes: 554058, scoped: true }), CTX),
    ).toBeNull();
    expect(
      secretsRunner.sufficient(cov({ commits: 3, bytes: 900, scoped: false }), CTX),
    ).toBeNull();
  });

  it("refuses a scan that walked commits but read 0 bytes", () => {
    const reason = secretsRunner.sufficient(
      cov({ commits: 5, bytes: 0, scoped: true }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/0 bytes/);
  });
});
