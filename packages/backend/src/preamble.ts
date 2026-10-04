/**
 * Builds the out-of-band configuration line written at the start of every
 * forward connection. The line must be exactly one newline-terminated JSON
 * object, because the helper reads up to the first newline.
 */
import type { Settings } from "./settings";

export const MAGIC = "TLSIMPOSTER/1 ";

export type PreambleArgs = {
  token: string;
  host: string;
  port: number;
  tls: boolean;
  sni: string | null;
  profile: string;
  clientHello: string | null;
  timeoutSec: number;
};

/**
 * Returns a string, not bytes: TextEncoder does not exist in Caido's QuickJS
 * backend runtime, and `Bytes = string | Array<number> | Uint8Array`, so
 * Connection.send accepts this directly. The result is pure ASCII because
 * JSON.stringify escapes everything above U+007F.
 */
export function buildPreamble(args: PreambleArgs): string {
  if (args.token.includes("\n") || args.token.includes("\r")) {
    throw new Error("preamble: token contains a line break");
  }

  const payload = {
    token: args.token,
    target: { host: args.host, port: args.port, tls: args.tls },
    sni: args.sni,
    profile: args.profile,
    clientHello: args.clientHello,
    timeoutSec: args.timeoutSec,
  };

  const json = JSON.stringify(payload);
  // JSON.stringify escapes newlines inside strings, so a literal one here would
  // mean the serializer failed us; refuse rather than send a split line.
  if (json.includes("\n")) {
    throw new Error("preamble: serialized configuration contains a newline");
  }

  return MAGIC + json + "\n";
}

/** Chooses the fingerprint for this request from the current settings. */
export function preambleArgsFor(
  settings: Settings,
  token: string,
  info: { host: string; port: number; tls: boolean; sni: string | null },
): PreambleArgs {
  const captured =
    settings.source === "captured" ? settings.capture.last?.clientHello ?? null : null;

  return {
    token,
    host: info.host,
    port: info.port,
    tls: info.tls,
    sni: info.sni,
    // The profile travels even with a captured hello: it supplies the HTTP/2
    // layer, which a ClientHello says nothing about.
    profile: settings.profile,
    clientHello: captured,
    timeoutSec: settings.timeoutSec,
  };
}
