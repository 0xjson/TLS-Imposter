/**
 * The deny mechanism.
 *
 * Caido fails open: an exception in `onUpstream` is logged and the request is
 * then sent by Caido itself, with Caido's own TLS fingerprint (Task 1, spec
 * 11.1.1 Q4). The only way to deny a request is to hand Caido a connection that
 * answers for us, so this is a loopback listener that replies 502 to anything.
 */
import { createServer, type Server, type Socket } from "net";

const BODY =
  "Awesome TLS: the fingerprint helper is unavailable, so this request was " +
  "blocked rather than sent with Caido's own TLS fingerprint.\n";

const RESPONSE =
  "HTTP/1.1 502 Bad Gateway\r\n" +
  "Content-Type: text/plain; charset=utf-8\r\n" +
  "X-Awesome-Tls-Error: helper unavailable\r\n" +
  `Content-Length: ${BODY.length}\r\n` +
  "Connection: close\r\n" +
  "\r\n" +
  BODY;

export type FallbackResponder = {
  port: number;
  close(): void;
};

export function startFallbackResponder(
  log: (level: "info" | "warn" | "error", msg: string) => void,
): Promise<FallbackResponder> {
  return new Promise((resolve, reject) => {
    const server: Server = createServer((sock: Socket) => {
      // Answer without reading: the request content is irrelevant, and not
      // waiting for it avoids stalling on a client that writes nothing.
      sock.on("error", () => {});
      sock.end(RESPONSE);
    });

    server.on("error", (err: Error) => {
      log("error", `Awesome TLS: fallback responder error: ${err.message}`);
      reject(err);
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr !== null ? addr.port : 0;
      if (port === 0) {
        reject(new Error("fallback responder got no port"));
        return;
      }
      let closed = false;
      resolve({
        port,
        close: () => {
          if (closed) return;
          closed = true;
          server.close();
        },
      });
    });
  });
}
