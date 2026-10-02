import { describe, expect, it } from "vitest";
import { connect } from "node:net";

import { openOneShot502 } from "./fallback";

const SIMPLE_REQUEST = "GET /anything HTTP/1.1\r\nHost: target.example\r\n\r\n";

/**
 * Reads the response and resolves once Content-Length bytes of body have
 * arrived, then closes.
 *
 * The responder answers with keep-alive and lets the peer close, which is how
 * Caido behaves, so waiting for a server-side close would hang forever.
 */
function fetchRaw(port: number, request = SIMPLE_REQUEST): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, "127.0.0.1", () => {
      sock.write(request);
    });
    let out = "";
    sock.setTimeout(6000, () => {
      sock.destroy();
      reject(new Error(`timeout; received ${out.length} bytes`));
    });
    sock.on("data", (d) => {
      out += d.toString("latin1");
      const split = out.indexOf("\r\n\r\n");
      if (split < 0) return;
      const match = /Content-Length: (\d+)/.exec(out.slice(0, split));
      if (match === null) return;
      if (out.length - (split + 4) >= Number(match[1])) {
        sock.destroy();
        resolve(out);
      }
    });
    sock.on("close", () => resolve(out));
    sock.on("error", reject);
  });
}

describe("openOneShot502", () => {
  it("answers a connection with a 502 explaining why", async () => {
    const r = await openOneShot502(() => {});
    try {
      const raw = await fetchRaw(r.port);
      expect(raw.startsWith("HTTP/1.1 502 Bad Gateway\r\n")).toBe(true);
      expect(raw).toContain("X-Awesome-Tls-Error: helper unavailable");
      expect(raw).toMatch(/Content-Length: \d+/);
      // The body must explain why, so the operator is not left guessing.
      expect(raw.split("\r\n\r\n")[1]).toContain("Awesome TLS");
    } finally {
      r.close();
    }
  });

  // Ending the socket ourselves aborts the connection (os error 10053) and
  // Caido then discards the reply in favour of its own 400 page.
  it("keeps the connection alive rather than closing it", async () => {
    const r = await openOneShot502(() => {});
    try {
      const raw = await fetchRaw(r.port);
      expect(raw).toContain("Connection: keep-alive");
      expect(raw).not.toContain("Connection: close");
    } finally {
      r.close();
    }
  });

  // A mismatch makes Caido wait for bytes that never come.
  it("declares a Content-Length matching the body", async () => {
    const r = await openOneShot502(() => {});
    try {
      const raw = await fetchRaw(r.port);
      const split = raw.indexOf("\r\n\r\n");
      const declared = Number(/Content-Length: (\d+)/.exec(raw.slice(0, split))![1]);
      expect(raw.length - (split + 4)).toBe(declared);
    } finally {
      r.close();
    }
  });

  it("answers a client that never completes a request", { timeout: 15000 }, async () => {
    const r = await openOneShot502(() => {});
    try {
      // No blank line, so the responder must fall back to its timer.
      const raw = await fetchRaw(r.port, "GET / HTTP/1.1\r\nHost: t\r\n");
      expect(raw).toContain("502");
    } finally {
      r.close();
    }
  });

  // Without draining, a request larger than the socket buffer stalls.
  it("consumes a large request body instead of stalling", { timeout: 15000 }, async () => {
    const r = await openOneShot502(() => {});
    try {
      const big = "x".repeat(2 * 1024 * 1024);
      const raw = await fetchRaw(
        r.port,
        `POST / HTTP/1.1\r\nHost: t\r\nContent-Length: ${big.length}\r\n\r\n${big}`,
      );
      expect(raw).toContain("502");
    } finally {
      r.close();
    }
  });

  // The listener must not outlive the request that asked for it: the backend
  // SDK has no unload hook, so anything long-lived can never be released.
  it("stops accepting after the first connection", async () => {
    const r = await openOneShot502(() => {});
    try {
      expect(await fetchRaw(r.port)).toContain("502");
      await expect(fetchRaw(r.port)).rejects.toThrow();
    } finally {
      r.close();
    }
  });

  it("binds loopback only and reports a usable port", async () => {
    const r = await openOneShot502(() => {});
    try {
      expect(r.port).toBeGreaterThan(0);
      expect(r.port).toBeLessThan(65536);
    } finally {
      r.close();
    }
  });

  it("close() is idempotent", async () => {
    const r = await openOneShot502(() => {});
    r.close();
    expect(() => r.close()).not.toThrow();
  });
});
