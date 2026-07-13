import { beforeAll } from "vitest";
import dns from "node:dns";
import net from "node:net";

// The CI job is called "Test (hermetic — no network, no Docker, no browser)".
// That name was asserting a property the suite did not actually have: two ZAP
// tests were making a real HTTP request to whatever was listening on
// localhost:3000, which meant they passed on a laptop with a stray dev server
// and failed on a CI runner. A scanner that is about to become everyone's CI
// gate cannot itself have a flaky, machine-dependent gate.
//
// So the property is now ENFORCED rather than asserted. Every escape hatch to
// the outside world is replaced with something that throws, loudly, naming the
// test that reached for it. An accidental real fetch/DNS/socket doesn't go
// slow or flaky — it fails immediately with an explanation and a fix.
//
// This is deliberately stronger than running the suite offline: offline only
// proves nothing SUCCEEDED, and a hung connect still looks like a slow pass.
// This proves nothing was even ATTEMPTED, on any machine, forever.

const explain = (what: string, target: string) =>
  new Error(
    `HERMETIC SUITE VIOLATION: a test tried to use the network — ${what}(${target}).\n` +
      `Unit tests must not touch the network: they become slow, machine-dependent, and\n` +
      `they pass or fail based on what happens to be listening on the host (this is\n` +
      `exactly how the ZAP tests went green locally and red on CI — 42L-973).\n` +
      `Mock the boundary instead, e.g.:\n` +
      `  vi.mock("../../src/util/authgate.js", () => ({ probeTarget: async () => ({ ok: true }) }));\n` +
      `  vi.mock("node:dns", () => ({ promises: { resolve4: async () => ["1.2.3.4"], resolve6: async () => [] } }));`,
  );

beforeAll(() => {
  globalThis.fetch = (input: unknown): never => {
    throw explain("fetch", String(input instanceof Request ? input.url : input));
  };

  // dns.promises + callback API, both entry points.
  const dnsTrap = (name: string) => (host: unknown): never => {
    throw explain(`dns.${name}`, String(host));
  };
  for (const m of ["resolve", "resolve4", "resolve6", "lookup"] as const) {
    (dns.promises as unknown as Record<string, unknown>)[m] = dnsTrap(`promises.${m}`);
    (dns as unknown as Record<string, unknown>)[m] = dnsTrap(m);
  }

  // Anything that gets past the above and opens a raw socket (http.request,
  // undici's internal dispatcher, a stray library) dies here.
  net.Socket.prototype.connect = function connect(...args: unknown[]): never {
    throw explain("socket.connect", JSON.stringify(args[0] ?? ""));
  };
});
