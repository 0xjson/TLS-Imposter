import { describe, expect, it, vi } from "vitest";

import { enableForAllDomains, readRule } from "./routing";

/**
 * The id Caido hands the backend through `sdk.meta.id()`: its Caido-internal
 * plugin id, not the manifest id "tls-imposter-backend". Taken verbatim from a
 * live install, where it is also the `plugin_id` of the upstream rule row
 * (Caido 0.58.3).
 */
const META_ID = "3aec3301-7889-446d-be57-c9c5de37f113";

/** A GraphQL executor that answers from a script of responses. */
function executor(responses: unknown[]) {
  const calls: { query: string; variables?: Record<string, unknown> }[] = [];
  const execute = vi.fn(async (query: string, variables?: Record<string, unknown>) => {
    calls.push({ query, variables });
    return responses.shift() ?? { data: {} };
  });
  return { execute, calls };
}

function ruleRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "1",
    enabled: true,
    allowlist: ["*"],
    denylist: [],
    plugin: { id: META_ID },
    ...overrides,
  };
}

describe("readRule", () => {
  it("finds the rule keyed by the id sdk.meta.id() returns", async () => {
    const { execute } = executor([{ data: { upstreamPlugins: [ruleRow()] } }]);

    expect(await readRule(execute, META_ID)).toEqual({
      kind: "rule",
      rule: { id: "1", enabled: true, allowlist: ["*"], denylist: [] },
    });
  });

  it("returns the rule belonging to this plugin", async () => {
    const { execute } = executor([
      {
        data: {
          upstreamPlugins: [
            ruleRow({ id: "9", plugin: { id: "some-other-plugin" } }),
            ruleRow({ id: "10", enabled: false, allowlist: ["a.example"] }),
          ],
        },
      },
    ]);

    expect(await readRule(execute, META_ID)).toEqual({
      kind: "rule",
      rule: { id: "10", enabled: false, allowlist: ["a.example"], denylist: [] },
    });
  });

  it("reports none when the read succeeded and this plugin has no rule", async () => {
    const { execute } = executor([{ data: { upstreamPlugins: [] } }]);
    expect(await readRule(execute, META_ID)).toEqual({ kind: "none" });
  });

  // "none" and "unknown" were one `null` before, and the card turned that null
  // into "no traffic reaches this plugin yet" — a claim a failed read cannot
  // support (spec 11.3.3).
  it("reports unknown, with the reason, when the query errors", async () => {
    const { execute } = executor([{ errors: [{ message: "denied" }] }]);
    expect(await readRule(execute, META_ID)).toEqual({ kind: "unknown", reason: "denied" });
  });

  it("reports unknown when the executor itself rejects", async () => {
    const execute = vi.fn(async () => {
      throw new Error("GraphQL variables must be an object");
    }) as never;

    const state = await readRule(execute, META_ID);
    expect(state.kind).toBe("unknown");
    expect(state.kind === "unknown" && state.reason).toMatch(/variables must be an object/);
  });

  it("reports unknown when the response carries no upstreamPlugins field", async () => {
    const { execute } = executor([{ data: {} }]);
    expect(await readRule(execute, META_ID).then((s) => s.kind)).toBe("unknown");
  });
});

describe("enableForAllDomains", () => {
  it("creates a wildcard rule when none exists", async () => {
    const { execute, calls } = executor([
      { data: { upstreamPlugins: [] } },
      { data: { createUpstreamPlugin: { upstream: ruleRow({ id: "11" }) } } },
    ]);

    const rule = await enableForAllDomains(execute, META_ID);
    expect(rule).toMatchObject({ id: "11", enabled: true, allowlist: ["*"] });

    const mutation = calls.at(-1)!;
    expect(mutation.query).toContain("createUpstreamPlugin");
    expect(mutation.variables).toEqual({
      input: { pluginId: META_ID, allowlist: ["*"], denylist: [], enabled: true },
    });
  });

  // The defect this replaces: the id was translated through a `manifestId`
  // lookup over `pluginPackages`, which a Caido-internal id never matches, so
  // the rule was never found and the mutation never ran.
  it("passes sdk.meta.id() straight through, with no manifest lookup", async () => {
    const { execute, calls } = executor([
      { data: { upstreamPlugins: [] } },
      { data: { createUpstreamPlugin: { upstream: ruleRow({ id: "11" }) } } },
    ]);

    await enableForAllDomains(execute, META_ID);

    expect(calls.map((c) => c.query).join("\n")).not.toContain("pluginPackages");
    expect(calls).toHaveLength(2);
  });

  it("updates an existing rule rather than creating a second one", async () => {
    const { execute, calls } = executor([
      {
        data: {
          upstreamPlugins: [ruleRow({ id: "10", enabled: false, allowlist: ["old.example"] })],
        },
      },
      { data: { updateUpstreamPlugin: { upstream: ruleRow({ id: "10" }) } } },
    ]);

    const rule = await enableForAllDomains(execute, META_ID);
    expect(rule).toMatchObject({ id: "10", enabled: true, allowlist: ["*"] });

    const mutation = calls.at(-1)!;
    expect(mutation.query).toContain("updateUpstreamPlugin");
    // The schema takes id alongside input (verified against 0.58.3).
    expect(mutation.variables).toEqual({
      id: "10",
      input: { pluginId: META_ID, allowlist: ["*"], denylist: [], enabled: true },
    });
  });

  it("throws when the mutation reports errors", async () => {
    const { execute } = executor([
      { data: { upstreamPlugins: [] } },
      { errors: [{ message: "forbidden" }] },
    ]);
    await expect(enableForAllDomains(execute, META_ID)).rejects.toThrow(/forbidden/);
  });

  // A failed read used to look exactly like "no rule exists", so the create
  // branch ran and could install a second rule alongside the one it could not
  // see — defeating the duplicate guard this function exists to provide.
  it("refuses to mutate anything when the current rule cannot be read", async () => {
    const { execute, calls } = executor([{ errors: [{ message: "denied" }] }]);

    await expect(enableForAllDomains(execute, META_ID)).rejects.toThrow(/denied/);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.query).toContain("upstreamPlugins");
  });

  it("throws when the mutation returns no rule", async () => {
    const { execute } = executor([
      { data: { upstreamPlugins: [] } },
      { data: { createUpstreamPlugin: { upstream: null } } },
    ]);
    await expect(enableForAllDomains(execute, META_ID)).rejects.toThrow();
  });
});
