/**
 * Reads and writes Caido's own Upstream Plugins rules over GraphQL, so the
 * plugin page can offer a one-click "route everything through me".
 *
 * Finer-grained rules stay in Caido's settings; this module only implements the
 * wildcard shortcut and reports the current rule.
 *
 * Every call here is keyed by the plugin's Caido-internal id, which is exactly
 * what `sdk.meta.id()` hands the backend: a UUID such as
 * "3aec3301-7889-446d-be57-c9c5de37f113" — the same id `sdk.meta.path()` is
 * named after and the same one the upstream rule row stores. It is *not* the
 * manifest id "awesome-tls-backend", so it must be passed straight through
 * rather than looked up (spec 11.3.3).
 */

export type UpstreamRule = {
  id: string;
  enabled: boolean;
  allowlist: string[];
  denylist: string[];
};

export type GraphQLExecute = <T>(
  query: string,
  variables?: Record<string, unknown>,
) => Promise<{ data?: T; errors?: { message: string }[] }>;

const RULES_QUERY = `
  query awesomeTlsUpstreamPlugins {
    upstreamPlugins { id enabled allowlist denylist plugin { id } }
  }
`;

const CREATE_MUTATION = `
  mutation awesomeTlsCreateUpstream($input: CreateUpstreamPluginInput!) {
    createUpstreamPlugin(input: $input) {
      upstream { id enabled allowlist denylist plugin { id } }
    }
  }
`;

const UPDATE_MUTATION = `
  mutation awesomeTlsUpdateUpstream($id: ID!, $input: UpdateUpstreamPluginInput!) {
    updateUpstreamPlugin(id: $id, input: $input) {
      upstream { id enabled allowlist denylist plugin { id } }
    }
  }
`;

type RuleRow = UpstreamRule & { plugin: { id: string } };

function firstError(res: { errors?: { message: string }[] }): string | null {
  return res.errors?.[0]?.message ?? null;
}

export async function readRule(
  execute: GraphQLExecute,
  pluginId: string,
): Promise<UpstreamRule | null> {
  const res = await execute<{ upstreamPlugins: RuleRow[] }>(RULES_QUERY);
  if (firstError(res) !== null) return null;

  const row = (res.data?.upstreamPlugins ?? []).find((r) => r.plugin.id === pluginId);
  if (row === undefined) return null;
  return strip(row);
}

/**
 * Points every domain at this plugin, updating an existing rule in place so
 * repeated clicks cannot pile up duplicates.
 */
export async function enableForAllDomains(
  execute: GraphQLExecute,
  pluginId: string,
): Promise<UpstreamRule> {
  const existing = await readRule(execute, pluginId);
  const input = { pluginId, allowlist: ["*"], denylist: [], enabled: true };

  if (existing === null) {
    const res = await execute<{ createUpstreamPlugin: { upstream: RuleRow | null } }>(
      CREATE_MUTATION,
      { input },
    );
    const err = firstError(res);
    if (err !== null) throw new Error(`Awesome TLS: ${err}`);
    const upstream = res.data?.createUpstreamPlugin.upstream;
    if (!upstream) throw new Error("Awesome TLS: Caido created no upstream rule");
    return strip(upstream);
  }

  const res = await execute<{ updateUpstreamPlugin: { upstream: RuleRow | null } }>(
    UPDATE_MUTATION,
    { id: existing.id, input },
  );
  const err = firstError(res);
  if (err !== null) throw new Error(`Awesome TLS: ${err}`);
  const upstream = res.data?.updateUpstreamPlugin.upstream;
  if (!upstream) throw new Error("Awesome TLS: Caido returned no upstream rule");
  return strip(upstream);
}

function strip(row: RuleRow): UpstreamRule {
  return {
    id: row.id,
    enabled: row.enabled,
    allowlist: row.allowlist,
    denylist: row.denylist,
  };
}
