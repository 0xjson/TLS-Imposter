import { describe, expect, it, vi } from "vitest";

import { makeUpstreamHandler } from "./upstream";
import { DEFAULTS, type Settings } from "./settings";

type FakeConn = {
  send: ReturnType<typeof vi.fn<(bytes: string) => Promise<void>>>;
  receive: ReturnType<typeof vi.fn>;
};

function fakeSdk(conn: FakeConn) {
  return {
    // Typed parameter so mock.calls[0] is a one-element tuple rather than [].
    net: { connect: vi.fn(async (_target: string) => conn) },
    console: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
}

// Mirrors the RUNTIME shape (isTLS/SNI), not the SDK's declared tls/sni.
// Reading info.tls returns undefined against Caido 0.58.3 (Task 1, spec 11.1.1).
function fakeRequest(info: { host: string; port: number; tls: boolean; sni?: string }) {
  return {
    getInfo: () => ({
      host: info.host,
      port: info.port,
      isTLS: info.tls,
      SNI: info.sni,
    }),
  };
}

function deps(
  overrides: {
    endpoint?: { port: number; token: string } | null;
    settings?: Settings;
    fallbackPort?: number | null;
  } = {},
) {
  const endpoint =
    overrides.endpoint === undefined ? { port: 51234, token: "tok" } : overrides.endpoint;
  const fallbackPort = overrides.fallbackPort === undefined ? 59999 : overrides.fallbackPort;
  return {
    openDenial: async () => fallbackPort,
    helper: {
      endpoint: () => endpoint,
      state: () => ({ kind: "running" as const }),
    },
    settings: { get: () => overrides.settings ?? DEFAULTS },
    log: vi.fn(),
  };
}

describe("upstream handler", () => {
  it("returns a loopback connection with the preamble already written", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    const handler = makeUpstreamHandler(deps());

    const result = await handler(
      sdk as never,
      fakeRequest({ host: "example.com", port: 443, tls: true }) as never,
    );

    expect(sdk.net.connect).toHaveBeenCalledTimes(1);
    const dialed = String(sdk.net.connect.mock.calls[0]![0]);
    expect(dialed).toContain("127.0.0.1");
    expect(dialed).toContain("51234");

    expect(conn.send).toHaveBeenCalledTimes(1);
    const sent = conn.send.mock.calls[0]![0] as string;
    expect(sent.startsWith("AWESOMETLS/1 ")).toBe(true);
    expect(sent).toContain('"host":"example.com"');
    expect(sent.endsWith("\n")).toBe(true);

    expect(result).toEqual({ connection: conn });
  });

  // The whole point: the SDK types say `tls`, the runtime says `isTLS`.
  // Reading the wrong one sends every HTTPS request as plaintext.
  it("reads isTLS from the runtime object, not the typed tls field", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const handler = makeUpstreamHandler(deps());
    await handler(
      fakeSdk(conn) as never,
      fakeRequest({ host: "h", port: 443, tls: true }) as never,
    );

    const sent = conn.send.mock.calls[0]![0] as string;
    expect(sent).toContain('"tls":true');
  });

  it("passes the target's own port and TLS flag through", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const handler = makeUpstreamHandler(deps());
    await handler(
      fakeSdk(conn) as never,
      fakeRequest({ host: "h", port: 8080, tls: false }) as never,
    );

    const sent = conn.send.mock.calls[0]![0] as string;
    expect(sent).toContain('"port":8080');
    expect(sent).toContain('"tls":false');
  });

  it("forwards an SNI override from the runtime SNI field", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const handler = makeUpstreamHandler(deps());
    await handler(
      fakeSdk(conn) as never,
      fakeRequest({ host: "h", port: 443, tls: true, sni: "sni.example" }) as never,
    );

    const sent = conn.send.mock.calls[0]![0] as string;
    expect(sent).toContain('"sni":"sni.example"');
  });

  it("routes to the 502 responder when the helper is down, not to the target", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    const handler = makeUpstreamHandler(deps({ endpoint: null }));

    const result = await handler(
      sdk as never,
      fakeRequest({ host: "h", port: 443, tls: true }) as never,
    );

    // Caido fails open, so denial means handing back our own responder.
    const dialed = String(sdk.net.connect.mock.calls[0]![0]);
    expect(dialed).toContain("127.0.0.1");
    expect(dialed).toContain("59999");
    expect(result).toEqual({ connection: conn });
    // No preamble: the responder is not the helper and speaks no protocol.
    expect(conn.send).not.toHaveBeenCalled();
  });

  it("throws only when the responder is also unavailable", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    const handler = makeUpstreamHandler(deps({ endpoint: null, fallbackPort: null }));

    await expect(
      handler(sdk as never, fakeRequest({ host: "h", port: 443, tls: true }) as never),
    ).rejects.toThrow(/502 responder/i);
  });

  it("propagates a connect failure rather than returning undefined", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    sdk.net.connect = vi.fn(async (_target: string) => {
      throw new Error("ECONNREFUSED");
    });
    const handler = makeUpstreamHandler(deps());

    await expect(
      handler(sdk as never, fakeRequest({ host: "h", port: 443, tls: true }) as never),
    ).rejects.toThrow();
  });

  it("propagates a preamble write failure", async () => {
    const conn: FakeConn = {
      send: vi.fn(async (_bytes: string) => {
        throw new Error("broken pipe");
      }),
      receive: vi.fn(),
    };
    const handler = makeUpstreamHandler(deps());

    await expect(
      handler(fakeSdk(conn) as never, fakeRequest({ host: "h", port: 443, tls: true }) as never),
    ).rejects.toThrow(/broken pipe/);
  });

  it("never logs the token", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const d = deps({ endpoint: { port: 51234, token: "SUPERSECRET" } });
    const handler = makeUpstreamHandler(d);
    await handler(fakeSdk(conn) as never, fakeRequest({ host: "h", port: 443, tls: true }) as never);

    expect(JSON.stringify(d.log.mock.calls)).not.toContain("SUPERSECRET");
  });

  it("survives a getInfo that throws, still denying the request", async () => {
    const conn: FakeConn = { send: vi.fn(async (_bytes: string) => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    const handler = makeUpstreamHandler(deps({ endpoint: null }));
    const broken = {
      getInfo: () => {
        throw new Error("no info");
      },
    };

    // The log line is best-effort; denial must still happen.
    const result = await handler(sdk as never, broken as never);
    expect(result).toEqual({ connection: conn });
  });
});
