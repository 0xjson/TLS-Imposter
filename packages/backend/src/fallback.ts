/**
 * The deny mechanism.
 *
 * Caido fails open: an exception in `onUpstream` is logged and the request is
 * then sent by Caido itself, with Caido's own TLS fingerprint (Task 1, spec
 * 11.1.1 Q4). The only way to deny a request is to hand Caido a connection
 * that answers for us, so this opens a loopback listener that replies 502.
 *
 * The listener is deliberately **one-shot**: it serves a single connection and
 * closes itself. Caido's backend SDK exposes no unload hook (its only events
 * are onInterceptRequest, onInterceptResponse, onProjectChange and onUpstream),
 * so anything opened in `init` can never be deliberately released. A long-lived
 * listener leaked, and appeared to wedge Caido's backend while it was stopping
 * the plugin. Opening one per denied request means the steady state — a healthy
 * helper — holds no extra socket at all.
 */
import { createServer, type Server, type Socket } from "net";

const BODY =
  "TLS Imposter: the fingerprint helper is unavailable, so this request was " +
  "blocked rather than sent with Caido's own TLS fingerprint.\n";

/**
 * `Connection: keep-alive`, and written rather than ended.
 *
 * Ending the socket ourselves aborts the connection (os error 10053, "an
 * established connection was aborted by the software in your host machine")
 * and Caido then discards the reply and serves its own 400 page. The Task 1
 * probe was relayed correctly because it wrote a keep-alive response and let
 * the peer close.
 */
const RESPONSE =
  "HTTP/1.1 502 Bad Gateway\r\n" +
  "Content-Type: text/plain; charset=utf-8\r\n" +
  "X-Tls-Imposter-Error: helper unavailable\r\n" +
  `Content-Length: ${BODY.length}\r\n` +
  "Connection: keep-alive\r\n" +
  "\r\n" +
  BODY;

/** How long to wait for a request before answering anyway. */
const SILENT_CLIENT_MS = 2_000;

/** Cap on how much of a request we buffer while looking for the header end. */
const MAX_REQUEST_PEEK = 64 * 1024;

/**
 * How long the one-shot listener waits to be used before giving up, so a
 * denied request that Caido never dials cannot leak a socket.
 */
const UNUSED_LISTENER_MS = 30_000;

export type OneShot502 = {
  /** Loopback port to hand Caido. */
  port: number;
  /** Releases the listener and any socket, safe to call more than once. */
  close(): void;
};

/**
 * Opens a loopback listener that answers the first connection with 502 and
 * then closes itself.
 */
export function openOneShot502(
  log: (level: "info" | "warn" | "error", msg: string) => void,
): Promise<OneShot502> {
  return new Promise((resolve, reject) => {
    let sock: Socket | null = null;
    let closed = false;
    let unused: ReturnType<typeof setTimeout> | null = null;

    const server: Server = createServer((incoming: Socket) => {
      sock = incoming;
      if (unused !== null) {
        clearTimeout(unused);
        unused = null;
      }
      // Only one connection is ever served, so stop accepting at once.
      server.close();

      incoming.on("error", () => {});

      // Read the request before answering. Caido writes the request into the
      // connection and then reads; answering first makes it discard the reply.
      let seen = "";
      let answered = false;

      const answer = () => {
        if (answered) return;
        answered = true;
        clearTimeout(silent);
        incoming.write(RESPONSE);
      };

      const silent = setTimeout(answer, SILENT_CLIENT_MS);

      incoming.on("data", (chunk: Buffer) => {
        if (answered) return; // already replying; drain the rest
        // latin1 keeps bytes 1:1; only the header delimiter matters here.
        seen += chunk.toString("latin1");
        if (seen.includes("\r\n\r\n") || seen.length > MAX_REQUEST_PEEK) {
          answer();
        }
      });

      incoming.on("end", answer);
      incoming.on("close", () => {
        clearTimeout(silent);
      });
    });

    server.on("error", (err: Error) => {
      log("error", `TLS Imposter: 502 responder error: ${err.message}`);
      reject(err);
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr !== null ? addr.port : 0;
      if (port === 0) {
        server.close();
        reject(new Error("502 responder got no port"));
        return;
      }

      const close = () => {
        if (closed) return;
        closed = true;
        if (unused !== null) {
          clearTimeout(unused);
          unused = null;
        }
        sock?.destroy();
        server.close();
      };

      // Nothing may outlive the request that asked for it.
      unused = setTimeout(close, UNUSED_LISTENER_MS);

      resolve({ port, close });
    });
  });
}
