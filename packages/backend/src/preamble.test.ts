import { describe, expect, it } from "vitest";

import { buildPreamble, preambleArgsFor } from "./preamble";
import { DEFAULTS, type Settings } from "./settings";

const args = {
  token: "abc123",
  host: "example.com",
  port: 443,
  tls: true,
  sni: null,
  profile: "chrome_150",
  clientHello: null,
  timeoutSec: 30,
};

function decode(text: string): { magic: string; json: Record<string, unknown> } {
  expect(text.endsWith("\n")).toBe(true);
  const space = text.indexOf(" ");
  return {
    magic: text.slice(0, space + 1),
    json: JSON.parse(text.slice(space + 1, -1)) as Record<string, unknown>,
  };
}

describe("buildPreamble", () => {
  it("emits the magic prefix, one JSON object and a trailing newline", () => {
    const { magic, json } = decode(buildPreamble(args));
    expect(magic).toBe("TLSIMPOSTER/1 ");
    expect(json).toEqual({
      token: "abc123",
      target: { host: "example.com", port: 443, tls: true },
      sni: null,
      profile: "chrome_150",
      clientHello: null,
      timeoutSec: 30,
    });
  });

  // The runtime has no TextEncoder, and Bytes accepts a string (Task 1).
  it("returns a string, not bytes", () => {
    expect(typeof buildPreamble(args)).toBe("string");
  });

  it("contains exactly one newline, at the very end", () => {
    const text = buildPreamble(args);
    expect(text.split("\n")).toHaveLength(2);
    expect(text.indexOf("\n")).toBe(text.length - 1);
  });

  it("carries an SNI override and a captured hello when given", () => {
    const { json } = decode(buildPreamble({ ...args, sni: "other.example", clientHello: "160301aa" }));
    expect(json.sni).toBe("other.example");
    expect(json.clientHello).toBe("160301aa");
  });

  it("keeps a punycode host intact without a stray newline", () => {
    const { json } = decode(buildPreamble({ ...args, host: "xn--caf-dma.example" }));
    expect(json.target).toMatchObject({ host: "xn--caf-dma.example" });
  });

  // JSON.stringify escapes control characters, so a hostile host cannot forge a
  // second preamble line; assert that rather than trusting it.
  it("escapes a newline inside a field instead of splitting the line", () => {
    const text = buildPreamble({ ...args, host: "evil\nTLSIMPOSTER/1 {}" });
    expect(text.split("\n")).toHaveLength(2);
    const { json } = decode(text);
    expect((json.target as Record<string, unknown>).host).toBe("evil\nTLSIMPOSTER/1 {}");
  });

  it("rejects a token containing a line break, which would forge a second line", () => {
    expect(() => buildPreamble({ ...args, token: "abc\ndef" })).toThrow();
    expect(() => buildPreamble({ ...args, token: "abc\rdef" })).toThrow();
  });
});

describe("preambleArgsFor", () => {
  it("uses the preset profile and no hello when the source is preset", () => {
    const settings: Settings = { ...DEFAULTS, source: "preset", profile: "firefox_148" };
    const got = preambleArgsFor(settings, "tok", { host: "h.example", port: 8443, tls: true, sni: null });

    expect(got.profile).toBe("firefox_148");
    expect(got.clientHello).toBeNull();
    expect(got).toMatchObject({ host: "h.example", port: 8443, tls: true, sni: null });
  });

  it("supplies the captured hello when the source is captured", () => {
    const settings: Settings = {
      ...DEFAULTS,
      source: "captured",
      capture: {
        ...DEFAULTS.capture,
        last: { clientHello: "160301ff", ja3: "x", ja4: "y", capturedAt: "z" },
      },
    };
    const got = preambleArgsFor(settings, "tok", { host: "h", port: 443, tls: true, sni: null });
    expect(got.clientHello).toBe("160301ff");
    // The profile still travels: it supplies the HTTP/2 layer.
    expect(got.profile).toBe(settings.profile);
  });

  it("falls back to the preset when captured is selected but nothing was captured", () => {
    const settings: Settings = { ...DEFAULTS, source: "captured" };
    expect(
      preambleArgsFor(settings, "tok", { host: "h", port: 443, tls: true, sni: null }).clientHello,
    ).toBeNull();
  });

  it("passes an SNI override through and carries the timeout", () => {
    const got = preambleArgsFor({ ...DEFAULTS, timeoutSec: 45 }, "tok", {
      host: "h",
      port: 443,
      tls: true,
      sni: "sni.example",
    });
    expect(got.sni).toBe("sni.example");
    expect(got.timeoutSec).toBe(45);
  });

  it("preserves a plaintext target", () => {
    const got = preambleArgsFor(DEFAULTS, "tok", { host: "h", port: 80, tls: false, sni: null });
    expect(got.tls).toBe(false);
    expect(got.port).toBe(80);
  });
});
