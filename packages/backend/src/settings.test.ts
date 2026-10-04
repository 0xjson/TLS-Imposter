import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DEFAULTS, SettingsStore, validate } from "./settings";

// Includes the shipped default, as a real helper's list of 80-odd profiles
// does. Without it these cases exercise the fallback path by accident rather
// than the defaults they claim to assert.
const opts = {
  profiles: [DEFAULTS.profile, "chrome_150", "firefox_148"],
  fallbackProfile: "chrome_150",
};

describe("validate", () => {
  it("returns the defaults for absent input", () => {
    const { settings, warnings } = validate(undefined, opts);
    expect(settings).toEqual(DEFAULTS);
    expect(warnings).toEqual([]);
  });

  it("accepts a fully specified object unchanged", () => {
    const input = {
      source: "captured",
      profile: "firefox_148",
      timeoutSec: 45,
      capture: {
        enabled: true,
        listen: "127.0.0.1:9000",
        forwardTo: "127.0.0.1:8080",
        last: {
          clientHello: "16030100",
          ja3: "a".repeat(32),
          ja4: "t13d1516h2_aaa_bbb",
          capturedAt: "2026-10-03T00:00:00Z",
        },
      },
    };
    const { settings, warnings } = validate(input, opts);
    expect(settings).toEqual(input);
    expect(warnings).toEqual([]);
  });

  it("falls back and warns when the profile is unknown", () => {
    const { settings, warnings } = validate({ profile: "netscape_4" }, opts);
    expect(settings.profile).toBe(DEFAULTS.profile);
    expect(warnings.join(" ")).toContain("netscape_4");
  });

  // Before the helper reports, the profile list is unknown; a stored value must
  // not be silently rewritten just because it cannot be checked yet.
  it("accepts any profile while the list is still unknown", () => {
    const { settings, warnings } = validate(
      { profile: "safari_ios_26_0" },
      { profiles: [], fallbackProfile: "chrome_150" },
    );
    expect(settings.profile).toBe("safari_ios_26_0");
    expect(warnings).toEqual([]);
  });

  it("clamps an out-of-range timeout", () => {
    expect(validate({ timeoutSec: 0 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: 10_000 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: 1.5 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: -5 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: 60 }, opts).settings.timeoutSec).toBe(60);
  });

  it("rejects a non-loopback capture address", () => {
    const { settings, warnings } = validate({ capture: { listen: "0.0.0.0:8886" } }, opts);
    expect(settings.capture.listen).toBe(DEFAULTS.capture.listen);
    expect(warnings.join(" ")).toContain("loopback");
  });

  it("rejects a malformed capture address", () => {
    for (const bad of ["127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "nonsense", ""]) {
      const { settings } = validate({ capture: { forwardTo: bad } }, opts);
      expect(settings.capture.forwardTo, bad).toBe(DEFAULTS.capture.forwardTo);
    }
  });

  it("accepts localhost and ::1 as loopback", () => {
    expect(validate({ capture: { listen: "localhost:8886" } }, opts).settings.capture.listen)
      .toBe("localhost:8886");
    expect(validate({ capture: { listen: "[::1]:8886" } }, opts).settings.capture.listen)
      .toBe("[::1]:8886");
  });

  it("drops a captured hello that is not hex", () => {
    const { settings, warnings } = validate(
      { capture: { last: { clientHello: "zzz", ja3: "x", ja4: "y", capturedAt: "z" } } },
      opts,
    );
    expect(settings.capture.last).toBeNull();
    expect(warnings.join(" ")).toContain("hex");
  });

  it("drops a captured hello with an odd number of hex digits", () => {
    const { settings } = validate(
      { capture: { last: { clientHello: "abc", ja3: "x", ja4: "y", capturedAt: "z" } } },
      opts,
    );
    expect(settings.capture.last).toBeNull();
  });

  it("drops an incomplete captured hello record", () => {
    const { settings, warnings } = validate(
      { capture: { last: { clientHello: "160301" } } },
      opts,
    );
    expect(settings.capture.last).toBeNull();
    expect(warnings.length).toBeGreaterThan(0);
  });

  it("ignores an unknown source value", () => {
    expect(validate({ source: "telepathy" }, opts).settings.source).toBe(DEFAULTS.source);
  });

  it("survives hostile shapes without throwing", () => {
    for (const bad of [null, 42, "string", [], true, { capture: 7 }, { capture: { last: 1 } },
      { capture: { last: [] } }, { profile: 42 }, { timeoutSec: "30" }]) {
      expect(() => validate(bad, opts), JSON.stringify(bad)).not.toThrow();
    }
  });

  // Validation must be a pure function of its input: a second pass over its own
  // output must not drift.
  it("is idempotent", () => {
    const once = validate({ profile: "netscape_4", timeoutSec: 99999 }, opts).settings;
    const twice = validate(once, opts).settings;
    expect(twice).toEqual(once);
  });
});

describe("SettingsStore", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "tls-imposter-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("starts from the defaults when no file exists", async () => {
    const store = new SettingsStore(join(dir, "settings.json"));
    const warnings = await store.load(opts);
    expect(warnings).toEqual([]);
    expect(store.get()).toEqual(DEFAULTS);
  });

  it("persists an update and reloads it", async () => {
    const path = join(dir, "settings.json");
    const store = new SettingsStore(path);
    await store.load(opts);

    await store.update({ profile: "firefox_148", timeoutSec: 45 }, opts);
    expect(store.get().profile).toBe("firefox_148");
    expect(store.get().timeoutSec).toBe(45);

    const reloaded = new SettingsStore(path);
    await reloaded.load(opts);
    expect(reloaded.get().profile).toBe("firefox_148");
    expect(reloaded.get().timeoutSec).toBe(45);
  });

  it("merges a nested patch without dropping sibling fields", async () => {
    const store = new SettingsStore(join(dir, "settings.json"));
    await store.load(opts);
    await store.update({ capture: { enabled: true } }, opts);

    expect(store.get().capture.enabled).toBe(true);
    expect(store.get().capture.listen).toBe(DEFAULTS.capture.listen);
    expect(store.get().capture.forwardTo).toBe(DEFAULTS.capture.forwardTo);
  });

  it("recovers from a corrupt file instead of failing to start", async () => {
    const path = join(dir, "settings.json");
    writeFileSync(path, "{ this is not json");

    const store = new SettingsStore(path);
    const warnings = await store.load(opts);
    expect(store.get()).toEqual(DEFAULTS);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it("creates the directory when it does not exist", async () => {
    const path = join(dir, "nested", "deeper", "settings.json");
    const store = new SettingsStore(path);
    await store.load(opts);
    await store.update({ timeoutSec: 45 }, opts);
    expect(JSON.parse(readFileSync(path, "utf8")).timeoutSec).toBe(45);
  });

  it("writes readable JSON", async () => {
    const path = join(dir, "settings.json");
    const store = new SettingsStore(path);
    await store.load(opts);
    await store.update({ timeoutSec: 45 }, opts);

    const text = readFileSync(path, "utf8");
    expect(text).toContain("\n"); // pretty-printed, not one line
    expect(JSON.parse(text).timeoutSec).toBe(45);
  });

  it("round-trips a captured hello through disk", async () => {
    const path = join(dir, "settings.json");
    const store = new SettingsStore(path);
    await store.load(opts);

    const hello = {
      clientHello: "16030100aa",
      ja3: "f984bd5bc7358922cde86ed4471a2e89",
      ja4: "t13d1516h2_8daaf6152771_806a8c22fdea",
      capturedAt: "2026-10-03T01:02:03Z",
    };
    await store.update({ capture: { last: hello } }, opts);

    const reloaded = new SettingsStore(path);
    await reloaded.load(opts);
    expect(reloaded.get().capture.last).toEqual(hello);
  });

  it("can clear a captured hello", async () => {
    const store = new SettingsStore(join(dir, "settings.json"));
    await store.load(opts);
    await store.update(
      {
        capture: {
          last: { clientHello: "16030100", ja3: "a", ja4: "b", capturedAt: "c" },
        },
      },
      opts,
    );
    expect(store.get().capture.last).not.toBeNull();

    await store.update({ capture: { last: null } }, opts);
    expect(store.get().capture.last).toBeNull();
  });
});

// The shipped default must win over tls-client's library default, which tracks
// newest Chrome. Caido drives its own bundled Chromium, and a fingerprint from
// a newer Chrome than the browser sending the headers is the inconsistency this
// plugin exists to remove (measured: the bundled Chromium 147 produces
// chrome_146's JA4 exactly -- spec 11.3.5).
describe("default profile", () => {
  it("prefers the shipped default over the helper's library default", () => {
    const { settings, warnings } = validate(
      {},
      { profiles: ["chrome_146", "chrome_150", "chrome_152"], fallbackProfile: "chrome_150" },
    );
    expect(settings.profile).toBe(DEFAULTS.profile);
    expect(settings.profile).toBe("chrome_146");
    expect(warnings).toEqual([]);
  });

  it("falls back to the helper's default when the shipped one is absent", () => {
    const { settings } = validate(
      {},
      { profiles: ["chrome_150", "chrome_152"], fallbackProfile: "chrome_150" },
    );
    expect(settings.profile).toBe("chrome_150");
  });

  it("still replaces a stored profile the helper does not have", () => {
    const { settings, warnings } = validate(
      { profile: "chrome_999" },
      { profiles: ["chrome_146", "chrome_150"], fallbackProfile: "chrome_150" },
    );
    expect(settings.profile).toBe("chrome_146");
    expect(warnings[0]).toMatch(/chrome_999.*not available.*chrome_146/);
  });

  it("keeps a stored profile the helper does have", () => {
    const { settings } = validate(
      { profile: "chrome_152" },
      { profiles: ["chrome_146", "chrome_152"], fallbackProfile: "chrome_150" },
    );
    expect(settings.profile).toBe("chrome_152");
  });
});
