import { describe, it, expect } from "vitest";
import { ALL_RUNNERS } from "../src/runners/index.js";
import type { Coverage } from "../src/types.js";

// The contract is only worth anything if it is impossible to opt out of.
//
// TypeScript makes `sufficient()` mandatory, but a type is a weak guarantee
// here: the tempting shortcut for a new runner is to write `sufficient: () =>
// null` — satisfying the compiler while asserting, permanently and invisibly,
// that no evidence is ever needed. That is the original bug wearing the new
// contract's clothes.
//
// So this suite holds every runner in the registry to the SPIRIT of the rule:
// each one must reject SOMETHING. A runner that accepts empty coverage is a
// runner that will report a clean bill of health for a scan that never ran, and
// it fails here rather than in production six months from now.

/** Coverage with nothing in it — the shape a scanner that never ran produces. */
const NOTHING: Coverage = { trail: [], data: {}, provenance: "nothing ran" };

const CTX = {} as never;

describe("every runner in the registry honours the evidence contract", () => {
  it("registers each runner exactly once, with a unique id", () => {
    const ids = ALL_RUNNERS.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.length).toBeGreaterThan(0);
  });

  it.each(ALL_RUNNERS.map((r) => [r.id, r] as const))(
    "%s: observes and judges through the contract, and never grades itself",
    (_id, runner) => {
      expect(typeof runner.observe).toBe("function");
      expect(typeof runner.sufficient).toBe("function");
      // The status field is gone from the runner's vocabulary. There is no way
      // for it to hand back "ok" — that word belongs to the orchestrator now.
      expect("run" in runner).toBe(false);
    },
  );

  it.each(ALL_RUNNERS.map((r) => [r.id, r] as const))(
    "%s: REFUSES empty coverage — a scan that examined nothing is never a pass",
    (_id, runner) => {
      const reason = runner.sufficient(NOTHING, CTX);
      expect(
        reason,
        `${runner.id}.sufficient() accepted coverage showing nothing was examined. ` +
          `That makes "no findings" indistinguishable from "never looked" — the exact ` +
          `false clean this contract exists to prevent. Give it a real condition.`,
      ).not.toBeNull();
      expect(typeof reason).toBe("string");
      expect((reason as string).length).toBeGreaterThan(0);
    },
  );

  it.each(ALL_RUNNERS.map((r) => [r.id, r] as const))(
    "%s: explains its refusal in words an operator can act on — never a bare 'insufficient'",
    (_id, runner) => {
      const reason = runner.sufficient(NOTHING, CTX) as string;
      // The note is what an operator reads when their build goes red. "Not
      // enough evidence" tells them nothing; "0 lockfiles walked" tells them
      // exactly where to look.
      expect(reason.length).toBeGreaterThan(15);
      expect(reason).not.toMatch(/^insufficient$/i);
    },
  );
});
