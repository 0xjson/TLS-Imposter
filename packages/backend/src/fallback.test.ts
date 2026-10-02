import { describe, expect, it } from "vitest";
import { connect } from "node:net";

import { startFallbackResponder } from "./fallback";

/** Reads everything the responder writes, then resolves. */
function fetchRaw(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, "127.0.0.1", () => {
      sock.write("GET /anything HTTP/1.1\r\nHost: target.example\r\n\r\n");
    });
    let out = "";
    sock.setTimeout(5000, () => {
      sock.destroy();
      reject(new Error("timeout"));
    });
    sock.on("data", (d) => {
      out += d.toString("latin1");
    });
    sock.on("close", () => resolve(out));
    sock.on("error", reject);
  });
}

describe("startFallbackResponder", () => {
  it("answers any connection with a 502 and closes", async () => {
    const r = await startFallbackResponder(() => {});
    try {
      const raw = await fetchRaw(r.port);
      expect(raw.startsWith("HTTP/1.1 502 Bad Gateway\r\n")).toBe(true);
      expect(raw).toContain("X-Awesome-Tls-Error: helper unavailable");
      expect(raw).toContain("Connection: close");
      expect(raw).toMatch(/Content-Length: \d+/);
      // The body must explain why, so the operator is not left guessing.
      expect(raw.split("\r\n\r\n")[1]).toContain("Awesome TLS");
    } finally {
      r.close();
    }
  });

  // The declared Content-Length must match the body exactly, or Caido hangs
  // waiting for bytes that never come.
  it("declares a Content-Length matching the body", async () => {
    const r = await startFallbackResponder(() => {});
    try {
      const raw = await fetchRaw(r.port);
      const [head, body] = raw.split("\r\n\r\n");
      const declared = Number(/Content-Length: (\d+)/.exec(head!)![1]);
      expect(body!.length).toBe(declared);
    } finally {
      r.close();
    }
  });

  it("answers even when the client sends nothing at all", async () => {
    const r = await startFallbackResponder(() => {});
    try {
      const raw = await new Promise<string>((resolve, reject) => {
        const sock = connect(r.port, "127.0.0.1");
        let out = "";
        sock.setTimeout(5000, () => {
          sock.destroy();
          reject(new Error("timeout waiting for a reply to a silent client"));
        });
        sock.on("data", (d) => {
          out += d.toString("latin1");
        });
        sock.on("close", () => resolve(out));
        sock.on("error", reject);
      });
      expect(raw).toContain("502");
    } finally {
      r.close();
    }
  });

  it("binds loopback only and reports a usable port", async () => {
    const r = await startFallbackResponder(() => {});
    try {
      expect(r.port).toBeGreaterThan(0);
      expect(r.port).toBeLessThan(65536);
    } finally {
      r.close();
    }
  });

  it("serves repeated connections", async () => {
    const r = await startFallbackResponder(() => {});
    try {
      for (let i = 0; i < 3; i++) {
        expect(await fetchRaw(r.port)).toContain("502");
      }
    } finally {
      r.close();
    }
  });

  it("close() is idempotent", async () => {
    const r = await startFallbackResponder(() => {});
    r.close();
    expect(() => r.close()).not.toThrow();
  });
});
