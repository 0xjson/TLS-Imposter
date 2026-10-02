/**
 * THROWAWAY PROBE — Task 1 of docs/superpowers/plans/2026-10-03-caido-awesome-tls.md
 *
 * Answers eight questions about how Caido actually drives onUpstream before the
 * real plugin is built on assumptions about it. Deleted in Task 1 Step 8.
 *
 * v2: TextDecoder/TextEncoder do not exist in Caido's QuickJS backend runtime
 * ("TextDecoder is not defined"). Uses Buffer for decoding, and passes the
 * preamble as a plain string since Bytes = string | Array<number> | Uint8Array.
 */
import type { SDK, DefineAPI } from "caido:plugin";
import type { RequestSpecRaw } from "caido:utils";
import { createServer, type Socket } from "net";
import { Buffer } from "buffer";

export type API = DefineAPI<{}>;

const PROBE = "[probe v4]";

export function init(sdk: SDK<API>) {
  let connectionSeq = 0;

  // Echo server standing in for the Go helper: logs exactly what Caido writes.
  const srv = createServer((sock: Socket) => {
    const id = ++connectionSeq;
    sdk.console.log(`${PROBE} conn#${id} opened`);

    // latin1 maps bytes 1:1 to code units, so string scanning is byte-exact.
    // Buffer.indexOf("\r\n\r\n") silently failed to match in this runtime.
    let seen = "";
    let requestsOnThisConn = 0;

    sock.on("data", (d: Buffer) => {
      seen += d.toString("latin1");
      sdk.console.log(
        `${PROBE} conn#${id} +${d.length}B total=${seen.length}B ` +
          `chunk=${JSON.stringify(d.toString("latin1"))}`,
      );

      const end = seen.indexOf("\r\n\r\n");
      if (end !== -1) {
        requestsOnThisConn++;
        sdk.console.log(
          `${PROBE} conn#${id} req${requestsOnThisConn} HEAD=` +
            JSON.stringify(seen.slice(0, end)),
        );
        const body = `probe-conn${id}-req${requestsOnThisConn}`;
        sock.write(
          "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain\r\n" +
            `X-Probe-Conn: ${id}\r\n` +
            `X-Probe-Req: ${requestsOnThisConn}\r\n` +
            `Content-Length: ${body.length}\r\n` +
            "Connection: keep-alive\r\n" +
            "\r\n" +
            body,
        );
        sdk.console.log(`${PROBE} conn#${id} responded to req${requestsOnThisConn}`);
        seen = seen.slice(end + 4);
      }
    });

    sock.on("error", (err: Error) => {
      sdk.console.log(`${PROBE} conn#${id} error: ${err.message}`);
    });
    sock.on("close", () => {
      sdk.console.log(
        `${PROBE} conn#${id} closed after ${requestsOnThisConn} request(s)`,
      );
    });
  });

  srv.on("error", (err: Error) => {
    sdk.console.error(`${PROBE} listener error: ${err.message}`);
  });

  srv.listen(0, "127.0.0.1", () => {
    const addr = srv.address();
    const port = typeof addr === "object" && addr !== null ? addr.port : 0;
    sdk.console.log(`${PROBE} echo server on 127.0.0.1:${port}`);

    sdk.events.onUpstream(async (eventSdk, request: RequestSpecRaw) => {
      // Q1: what does getInfo report, and does getRaw give HTTP/1.1 text?
      let host = "?";
      let port2 = -1;
      let tls = "?";
      let sni = "?";
      try {
        const info = request.getInfo();
        host = info.host;
        port2 = info.port;
        tls = String(info.tls);
        sni = String(info.sni);
        eventSdk.console.log(
          `${PROBE} onUpstream getInfo host=${host} port=${port2} tls=${tls} sni=${sni}`,
        );

        // `tls`/`sni` came back undefined in v2 while the GraphQL schema names
        // them isTLS/SNI. Discover what the runtime object actually exposes.
        const bag = info as unknown as Record<string, unknown>;
        const own = Object.keys(bag);
        const proto = Object.getPrototypeOf(bag) as object | null;
        const protoKeys = proto === null ? [] : Object.getOwnPropertyNames(proto);
        eventSdk.console.log(
          `${PROBE} getInfo ownKeys=${JSON.stringify(own)} ` +
            `protoKeys=${JSON.stringify(protoKeys)}`,
        );
        for (const k of ["tls", "isTLS", "isTls", "sni", "SNI", "scheme", "secure"]) {
          if (k in bag || bag[k] !== undefined) {
            eventSdk.console.log(`${PROBE} getInfo.${k} = ${JSON.stringify(bag[k])}`);
          }
        }
      } catch (err) {
        eventSdk.console.error(`${PROBE} getInfo threw: ${String(err)}`);
      }

      try {
        const bytes = request.getRaw();
        const raw = Buffer.from(bytes).toString("utf8");
        eventSdk.console.log(
          `${PROBE} onUpstream rawLen=${bytes.length} raw=${JSON.stringify(raw.slice(0, 500))}`,
        );
      } catch (err) {
        eventSdk.console.error(`${PROBE} getRaw threw: ${String(err)}`);
      }

      // Q4: what does Caido do when the callback throws? Triggered by path so
      // the target stays resolvable: a fallback then shows up as a real
      // upstream response, distinguishable from an outright failure.
      let rawText = "";
      try {
        rawText = Buffer.from(request.getRaw()).toString("latin1");
      } catch {
        rawText = "";
      }
      if (rawText.includes("probe-throw")) {
        eventSdk.console.log(`${PROBE} throwing deliberately for question 4`);
        throw new Error("probe deliberate throw");
      }

      // Q2: which connect form works, and does a pre-written preamble land
      // ahead of the request bytes?
      let connection;
      let form = "";
      try {
        connection = await eventSdk.net.connect(`tcp://127.0.0.1:${port}`);
        form = "tcp:// url";
      } catch (err) {
        eventSdk.console.log(`${PROBE} connect("tcp://...") failed: ${String(err)}`);
        try {
          connection = await eventSdk.net.connect(`127.0.0.1:${port}`);
          form = "bare host:port";
        } catch (err2) {
          eventSdk.console.error(`${PROBE} both connect forms failed: ${String(err2)}`);
          throw err2;
        }
      }
      eventSdk.console.log(`${PROBE} net.connect ok via ${form}`);

      // Bytes accepts a string, so no TextEncoder is needed.
      await connection.send(`PREAMBLE-MARKER host=${host} port=${port2}\n`);
      eventSdk.console.log(`${PROBE} preamble sent, returning connection`);
      return { connection };
    });

    sdk.console.log(`${PROBE} onUpstream registered`);
  });
}
