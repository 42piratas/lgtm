import { describe, it, expect } from "vitest";
import { classifyStrokeStyle, contrastRatio, type StrokeStyle } from "../../src/runners/a11y.js";

// 42L-973 #5, and the adversarial-review follow-up on it.
//
// axe reads a -webkit-text-stroke colour as the text foreground, so a
// compliant node gets reported failing. The fix downgrades those to a visible
// "needs review" note. The danger — and the thing this file exists to pin — is
// that downgrading EVERY stroked node trades a false positive for a false
// NEGATIVE: a stroked element whose fill genuinely fails contrast would
// quietly stop failing the build. That is the worse bug.
//
// So the rule is: downgrade ONLY on positive evidence that the real
// fill-vs-background ratio passes. Anything ambiguous keeps axe's hard
// failure. This is the pure decision function, tested without a browser.

const base: StrokeStyle = {
  strokeWidth: "3px",
  color: "rgb(74, 74, 74)", // #4A4A4A
  fontSize: "16px",
  fontWeight: "400",
  bgColors: ["rgba(0, 0, 0, 0)", "rgb(255, 255, 255)"], // transparent node, white body
  bgImages: ["none", "none"],
};

describe("contrastRatio — the WCAG formula itself", () => {
  it("computes the canonical extremes", () => {
    expect(contrastRatio([0, 0, 0, 1], [255, 255, 255, 1])).toBeCloseTo(21, 1);
    expect(contrastRatio([255, 255, 255, 1], [255, 255, 255, 1])).toBeCloseTo(1, 5);
  });

  it("is symmetric — order of fg/bg does not change the ratio", () => {
    const a = contrastRatio([74, 74, 74, 1], [255, 255, 255, 1]);
    const b = contrastRatio([255, 255, 255, 1], [74, 74, 74, 1]);
    expect(a).toBeCloseTo(b, 6);
  });

  it("matches the hand-computed value for the #4A4A4A-on-white fixture (8.86:1)", () => {
    // Hand-checked: L(#4A4A4A) = ((74/255 + 0.055)/1.055)^2.4 = 0.0685,
    // ratio = (1.0 + 0.05) / (0.0685 + 0.05) = 8.86. Comfortably above the
    // 4.5:1 AA threshold — which is the whole point of the fixture.
    expect(contrastRatio([74, 74, 74, 1], [255, 255, 255, 1])).toBeCloseTo(8.86, 1);
  });
});

describe("classifyStrokeStyle — no stroke means hands off", () => {
  it.each([["0px"], ["0"], [""]])("returns no-stroke for width %s", (strokeWidth) => {
    expect(classifyStrokeStyle({ ...base, strokeWidth })).toBe("no-stroke");
  });
});

describe("classifyStrokeStyle — downgrades ONLY a genuinely-compliant stroked node", () => {
  it("downgrades when the real fill passes AA at the normal-text threshold (8.86:1 >= 4.5)", () => {
    expect(classifyStrokeStyle(base)).toBe("stroke-fill-passes");
  });

  it("downgrades large text that passes the 3:1 large-text threshold but not 4.5:1", () => {
    // #949494 on white ≈ 3.2:1 — fails as normal text, passes as large text.
    const large: StrokeStyle = {
      ...base,
      color: "rgb(148, 148, 148)",
      fontSize: "28px",
    };
    expect(classifyStrokeStyle(large)).toBe("stroke-fill-passes");
  });

  it("does NOT downgrade that same colour at normal size — the threshold is applied honestly", () => {
    const normal: StrokeStyle = {
      ...base,
      color: "rgb(148, 148, 148)",
      fontSize: "16px",
    };
    expect(classifyStrokeStyle(normal)).toBe("stroke-fill-fails-or-unknown");
  });

  it("treats >=18.66px bold as large text (the WCAG bold rule)", () => {
    const boldLarge: StrokeStyle = {
      ...base,
      color: "rgb(148, 148, 148)",
      fontSize: "19px",
      fontWeight: "700",
    };
    expect(classifyStrokeStyle(boldLarge)).toBe("stroke-fill-passes");
  });
});

describe("classifyStrokeStyle — the false-negative guard (this is the important one)", () => {
  it("KEEPS the hard failure when the stroked node's real fill contrast is genuinely bad", () => {
    // #DDDDDD on white ≈ 1.3:1. axe flagged it (it read the light stroke), and
    // it *deserves* to be flagged — the fill is genuinely inaccessible. If this
    // ever returns stroke-fill-passes, we have silently stopped failing the
    // build on real, unreadable text.
    const bad: StrokeStyle = { ...base, color: "rgb(221, 221, 221)" };
    expect(classifyStrokeStyle(bad)).toBe("stroke-fill-fails-or-unknown");
  });

  it("keeps the hard failure for translucent text — we cannot be sure, so we do not downgrade", () => {
    const translucent: StrokeStyle = { ...base, color: "rgba(74, 74, 74, 0.4)" };
    expect(classifyStrokeStyle(translucent)).toBe("stroke-fill-fails-or-unknown");
  });

  it("keeps the hard failure over a background IMAGE — the effective background is unknowable from CSS", () => {
    const img: StrokeStyle = {
      ...base,
      bgImages: ["none", "linear-gradient(red, blue)"],
    };
    expect(classifyStrokeStyle(img)).toBe("stroke-fill-fails-or-unknown");
  });

  it("keeps the hard failure over a translucent background layer", () => {
    const translucentBg: StrokeStyle = {
      ...base,
      bgColors: ["rgba(0, 0, 0, 0.5)", "rgb(255, 255, 255)"],
    };
    expect(classifyStrokeStyle(translucentBg)).toBe("stroke-fill-fails-or-unknown");
  });

  it("keeps the hard failure when the colour is unparseable", () => {
    const weird: StrokeStyle = { ...base, color: "color(display-p3 0.1 0.2 0.3)" };
    expect(classifyStrokeStyle(weird)).toBe("stroke-fill-fails-or-unknown");
  });
});

describe("classifyStrokeStyle — background resolution", () => {
  it("walks past transparent ancestors to the nearest opaque background", () => {
    const nested: StrokeStyle = {
      ...base,
      bgColors: ["rgba(0, 0, 0, 0)", "rgba(0, 0, 0, 0)", "rgb(255, 255, 255)"],
      bgImages: ["none", "none", "none"],
    };
    expect(classifyStrokeStyle(nested)).toBe("stroke-fill-passes");
  });

  it("falls back to the white canvas default when nothing declares a background", () => {
    const noBg: StrokeStyle = {
      ...base,
      bgColors: ["rgba(0, 0, 0, 0)"],
      bgImages: ["none"],
    };
    expect(classifyStrokeStyle(noBg)).toBe("stroke-fill-passes"); // #4A4A4A on white
  });

  it("respects a dark opaque background — light text on dark passes, and is downgraded", () => {
    const dark: StrokeStyle = {
      ...base,
      color: "rgb(255, 255, 255)",
      bgColors: ["rgb(20, 20, 20)"],
      bgImages: ["none"],
    };
    expect(classifyStrokeStyle(dark)).toBe("stroke-fill-passes");
  });
});
