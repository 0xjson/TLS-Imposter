import { describe, expect, it, vi } from "vitest";

import { enableForAllDomains, findBackendPluginId, readRule } from "./routing";

/** A GraphQL executor that answers from a script of responses. */
function executor(responses: unknown[]) {
  const calls: { query: string; variables?: Record<string, unknown> }[] = [];
  const execute = vi.fn(async (query: string, variables?: Record<string, unknown>) => {
    calls.push({ query, variables });
    return responses.shift() ?? { data: {} };
  });
  return { execute, calls };
}

// The real schema nests plugins inside pluginPackages; `plugins` does not exist
// on QueryRoot (verified against Caido 0.58.3).
function packagesResponse() {
  return {
    data: {
      pluginPackages: [
        {
          id: "pkg0",
          plugins: [{ __typename: "PluginBackend", id: "99", manifestId: "other-plugin" }],
        },
        {
          id: "pkg1",
          plugins: [
            { __typename: "PluginFrontend", id: "1", manifestId: "awesome-tls-frontend" },
            { __typename: "PluginBackend", id: "42", manifestId: "awesome-tls-backend" },
          ],
        },
      ],
    },
  };
}

describe("findBackendPluginId", () => {
  it("matches on manifestId and the backend typename across packages", async () => {
    const { execute } = executor([packagesResponse()]);
    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBe("42");
  });

  it("queries pluginPackages, not plugins", async () => {
    const { execute, calls } = executor([packagesResponse()]);
    await findBackendPluginId(execute, "awesome-tls-backend");
    expect(calls[0]!.query).toContain("pluginPackages");
  });

  it("returns null when no plugin matches", async () => {
    const { execute } = executor([{ data: { pluginPackages: [] } }]);
    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBeNull();
  });

  it("returns null when the query errors instead of throwing", async () => {
    const { execute } = executor([{ errors: [{ message: "nope" }] }]);
    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBeNull();
  });

  it("tolerates a package with no plugins array", async () => {
    const { execute } = executor([{ data: { pluginPackages: [{ id: "pkg" }] } }]);
    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBeNull();
  });
});

describe("readRule", () => {
  it("returns the rule belonging to this plugin", async () => {
    const { execute } = executor([
      {
        data: {
          upstreamPlugins: [
            { id: "9", enabled: true, allowlist: ["*"], denylist: [], plugin: { id: "7" } },
            {
              id: "10",
              enabled: false,
              allowlist: ["a.example"],
              denylist: [],
              plugin: { id: "42" },
            },
          ],
        },
      },
    ]);

    expect(await readRule(execute, "42")).toEqual({
      id: "10",
      enabled: false,
      allowlist: ["a.example"],
      denylist: [],
    });
  });

  it("returns null when this plugin has no rule", async () => {
    const { execute } = executor([{ data: { upstreamPlugins: [] } }]);
    expect(await readRule(execute, "42")).toBeNull();
  });

  it("returns null when the query errors", async () => {
    const { execute } = executor([{ errors: [{ message: "denied" }] }]);
    expect(await readRule(execute, "42")).toBeNull();
  });
});

describe("enableForAllDomains", () => {
  it("creates a wildcard rule when none exists", async () => {
    const { execute, calls } = executor([
      packagesResponse(),
      { data: { upstreamPlugins: [] } },
      {
        data: {
          createUpstreamPlugin: {
            upstream: {
              id: "11",
              enabled: true,
              allowlist: ["*"],
              denylist: [],
              plugin: { id: "42" },
            },
          },
        },
      },
    ]);

    const rule = await enableForAllDomains(execute, "awesome-tls-backend");
    expect(rule).toMatchObject({ enabled: true, allowlist: ["*"] });

    const mutation = calls.at(-1)!;
    expect(mutation.query).toContain("createUpstreamPlugin");
    expect(mutation.variables).toEqual({
      input: { pluginId: "42", allowlist: ["*"], denylist: [], enabled: true },
    });
  });

  it("updates an existing rule rather than creating a second one", async () => {
    const { execute, calls } = executor([
      packagesResponse(),
      {
        data: {
          upstreamPlugins: [
            {
              id: "10",
              enabled: false,
              allowlist: ["old.example"],
              denylist: [],
              plugin: { id: "42" },
            },
          ],
        },
      },
      {
        data: {
          updateUpstreamPlugin: {
            upstream: {
              id: "10",
              enabled: true,
              allowlist: ["*"],
              denylist: [],
              plugin: { id: "42" },
            },
          },
        },
      },
    ]);

    const rule = await enableForAllDomains(execute, "awesome-tls-backend");
    expect(rule).toMatchObject({ id: "10", enabled: true, allowlist: ["*"] });

    const mutation = calls.at(-1)!;
    expect(mutation.query).toContain("updateUpstreamPlugin");
    // The schema takes id alongside input (verified against 0.58.3).
    expect(mutation.variables).toEqual({
      id: "10",
      input: { pluginId: "42", allowlist: ["*"], denylist: [], enabled: true },
    });
  });

  it("throws a clear error when the plugin id cannot be resolved", async () => {
    const { execute } = executor([{ data: { pluginPackages: [] } }]);
    await expect(enableForAllDomains(execute, "awesome-tls-backend")).rejects.toThrow(/plugin id/i);
  });

  it("throws when the mutation reports errors", async () => {
    const { execute } = executor([
      packagesResponse(),
      { data: { upstreamPlugins: [] } },
      { errors: [{ message: "forbidden" }] },
    ]);
    await expect(enableForAllDomains(execute, "awesome-tls-backend")).rejects.toThrow(/forbidden/);
  });

  it("throws when the mutation returns no rule", async () => {
    const { execute } = executor([
      packagesResponse(),
      { data: { upstreamPlugins: [] } },
      { data: { createUpstreamPlugin: { upstream: null } } },
    ]);
    await expect(enableForAllDomains(execute, "awesome-tls-backend")).rejects.toThrow();
  });
});
