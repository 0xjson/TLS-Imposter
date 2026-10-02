/**
 * The onUpstream hook: hands Caido a loopback connection to the helper with the
 * per-request configuration already written to it.
 *
 * This runs on the request hot path, so it does no I/O beyond one connect and
 * one write.
 */
import type { SDK } from "caido:plugin";
import type { Connection, RequestSpecRaw } from "caido:utils";

import { buildPreamble, preambleArgsFor } from "./preamble";
import type { Settings } from "./settings";

export type UpstreamDeps = {
  helper: {
    endpoint: () => { port: number; token: string } | null;
    state: () => { kind: string };
  };
  settings: { get(): Settings };
  /**
   * Opens a one-shot 502 responder and returns its loopback port, or null if
   * one could not be opened.
   */
  openDenial: () => Promise<number | null>;
  log: (level: "info" | "warn" | "error", msg: string) => void;
};

/**
 * ConnectionInfo exposes isTLS/SNI at runtime while the SDK types declare
 * tls/sni. Reading the typed names yields undefined, which would send every
 * HTTPS request as plaintext (Task 1, spec 11.1.1).
 */
type RuntimeConnectionInfo = {
  host: string;
  port: number;
  isTLS: boolean;
  SNI?: string;
};

/** Host:port of a request, for log lines only. */
function describeTarget(request: Pick<RequestSpecRaw, "getInfo">): string {
  try {
    const i = request.getInfo() as unknown as RuntimeConnectionInfo;
    return `${i.host}:${i.port}`;
  } catch {
    return "<unknown target>";
  }
}

export function makeUpstreamHandler(deps: UpstreamDeps) {
  return async function onUpstream(
    sdk: Pick<SDK, "net" | "console">,
    request: Pick<RequestSpecRaw, "getInfo">,
  ): Promise<{ connection: Connection }> {
    const endpoint = deps.helper.endpoint();

    if (endpoint === null) {
      // Fail closed. Task 1 proved that neither throwing nor returning
      // undefined denies the request: Caido logs the error and then sends it
      // itself with its own fingerprint. Handing back a connection to our own
      // 502 responder is the only way to stop it leaving the machine.
      const port = await deps.openDenial();
      if (port === null) {
        throw new Error(
          `Awesome TLS: helper is down (${deps.helper.state().kind}) and the ` +
            `502 responder could not be opened; request may leave unspoofed`,
        );
      }
      deps.log(
        "warn",
        `Awesome TLS: helper down; answering 502 for ${describeTarget(request)}`,
      );
      return { connection: await sdk.net.connect(`tcp://127.0.0.1:${port}`) };
    }

    const info = request.getInfo() as unknown as RuntimeConnectionInfo;
    const args = preambleArgsFor(deps.settings.get(), endpoint.token, {
      host: info.host,
      port: info.port,
      tls: info.isTLS === true,
      sni: info.SNI ?? null,
    });

    const connection = await sdk.net.connect(`tcp://127.0.0.1:${endpoint.port}`);
    await connection.send(buildPreamble(args));
    return { connection };
  };
}

/** Registers the hook with Caido. */
export function registerUpstream(sdk: SDK, deps: UpstreamDeps): void {
  const handler = makeUpstreamHandler(deps);
  sdk.events.onUpstream(async (eventSdk, request) => handler(eventSdk, request));
}
