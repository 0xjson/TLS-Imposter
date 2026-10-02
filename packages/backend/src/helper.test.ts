import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

import {
  BACKOFF_MS,
  HelperManager,
  MAX_FAILURES,
  READY_TIMEOUT_MS,
  type ChildHandle,
} from "./helper";

/**
 * A minimal emitter. @caido/quickjs-types declares its own "events" module,
 * which shadows @types/node's EventEmitter and leaves it without members, so
 * the tests carry their own rather than depending on which one wins.
 */
class Emitter {
  // `any` here is deliberate: ChildHandle declares narrow per-event callback
  // signatures, and a single generic handler type cannot be assignable to all
  // of them at once.
  /* eslint-disable @typescript-eslint/no-explicit-any */
  private handlers = new Map<string, ((...args: any[]) => void)[]>();

  on(event: string, cb: (...args: any[]) => void): this {
    const list = this.handlers.get(event) ?? [];
    list.push(cb);
    this.handlers.set(event, list);
    return this;
  }

  emit(event: string, ...args: any[]): void {
    for (const cb of [...(this.handlers.get(event) ?? [])]) cb(...args);
  }
  /* eslint-enable @typescript-eslint/no-explicit-any */
}

/** A scriptable stand-in for the helper process. */
class FakeChild extends Emitter implements ChildHandle {
  readonly written: string[] = [];
  killed = false;
  stdinClosed = false;
  readonly stdout = new Emitter();
  readonly stderr = new Emitter();

  write(line: string): void {
    this.written.push(line);
  }
  kill(): void {
    this.killed = true;
    this.emit("exit", 0);
  }
  closeStdin(): void {
    this.stdinClosed = true;
  }

  /** Emit one control message as the helper would. */
  say(msg: unknown): void {
    this.stdout.emit("data", JSON.stringify(msg) + "\n");
  }
  readyNow(port = 51234): void {
    this.say({
      type: "ready",
      port,
      token: "t".repeat(64),
      profiles: ["chrome_150", "firefox_148"],
      defaultProfile: "chrome_150",
      version: "0.1.0",
    });
  }
}

function setup() {
  const children: FakeChild[] = [];
  const spawner = vi.fn(() => {
    const c = new FakeChild();
    children.push(c);
    return c;
  });
  const states: unknown[] = [];
  const captured: unknown[] = [];
  const captureStates: unknown[] = [];
  const logs: unknown[] = [];

  const manager = new HelperManager({
    exe: "C:/fake/awesome-tls-helper.exe",
    spawn: spawner,
    onState: (s) => states.push(s),
    onCaptured: (c) => captured.push(c),
    onCaptureState: (s) => captureStates.push(s),
    log: (level, msg) => logs.push({ level, msg }),
  });

  return { manager, children, spawner, states, captured, captureStates, logs };
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("HelperManager", () => {
  it("reaches running once ready arrives, exposing port and profiles", async () => {
    const { manager, children } = setup();
    const started = manager.start();
    children[0]!.readyNow(51234);
    await started;

    const state = manager.state();
    expect(state.kind).toBe("running");
    if (state.kind === "running") {
      expect(state.port).toBe(51234);
      expect(state.profiles).toContain("firefox_148");
      expect(state.defaultProfile).toBe("chrome_150");
    }
    expect(manager.endpoint()?.port).toBe(51234);
    expect(manager.profiles()).toEqual(["chrome_150", "firefox_148"]);
  });

  it("never exposes the token through the public state", async () => {
    const { manager, children, states, logs } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    // endpoint() is internal and does carry the token; nothing else may.
    expect(JSON.stringify(states)).not.toContain("t".repeat(64));
    expect(JSON.stringify(manager.state())).not.toContain("t".repeat(64));
    expect(JSON.stringify(logs)).not.toContain("t".repeat(64));
    expect(manager.endpoint()?.token).toBe("t".repeat(64));
  });

  it("fails when ready never arrives", async () => {
    const { manager } = setup();
    const started = manager.start();
    await vi.advanceTimersByTimeAsync(READY_TIMEOUT_MS + 100);
    await started;

    expect(manager.state().kind).toBe("failed");
    expect(manager.endpoint()).toBeNull();
  });

  it("fails when ready is missing a port or token", async () => {
    const { manager, children } = setup();
    const started = manager.start();
    children[0]!.say({ type: "ready", port: 0, token: "", profiles: [] });
    await started;

    expect(manager.state().kind).toBe("failed");
    expect(manager.endpoint()).toBeNull();
  });

  it("restarts with backoff after an unexpected exit", async () => {
    const { manager, children, spawner } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    children[0]!.emit("exit", 1);
    expect(manager.state().kind).toBe("restarting");
    expect(spawner).toHaveBeenCalledTimes(1);
    // The endpoint must be withdrawn immediately, so no request is routed to a
    // dead helper.
    expect(manager.endpoint()).toBeNull();

    await vi.advanceTimersByTimeAsync(BACKOFF_MS[0]! + 10);
    expect(spawner).toHaveBeenCalledTimes(2);

    children[1]!.readyNow(51235);
    await vi.advanceTimersByTimeAsync(10);
    expect(manager.state().kind).toBe("running");
    expect(manager.endpoint()?.port).toBe(51235);
  });

  it("gives up after repeated rapid failures", async () => {
    const { manager, children } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    for (let i = 0; i <= MAX_FAILURES; i++) {
      children[children.length - 1]!.emit("exit", 1);
      await vi.advanceTimersByTimeAsync(31_000);
    }

    expect(manager.state().kind).toBe("failed");
  });

  it("does not restart after an intentional stop", async () => {
    const { manager, children, spawner } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    manager.stop();
    await vi.advanceTimersByTimeAsync(60_000);

    expect(manager.state().kind).toBe("stopped");
    expect(spawner).toHaveBeenCalledTimes(1);
    expect(manager.endpoint()).toBeNull();
  });

  // Closing stdin is the documented shutdown signal; kill is the fallback.
  it("closes stdin as well as killing on stop", async () => {
    const { manager, children } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    manager.stop();
    expect(children[0]!.stdinClosed).toBe(true);
    expect(children[0]!.killed).toBe(true);
  });

  it("forwards capture commands and surfaces capture state", async () => {
    const { manager, children, captureStates } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    manager.sendCapture(true, "127.0.0.1:8886", "127.0.0.1:8080");
    const sent = children[0]!.written.join("");
    expect(sent).toContain('"type":"capture"');
    expect(sent).toContain('"listen":"127.0.0.1:8886"');
    expect(sent.endsWith("\n")).toBe(true);

    children[0]!.say({ type: "capture-status", state: "listening", listen: "127.0.0.1:8886" });
    await vi.advanceTimersByTimeAsync(10);
    expect(captureStates.at(-1)).toMatchObject({
      state: "listening",
      listen: "127.0.0.1:8886",
    });
  });

  it("reports a rejected capture as an error state", async () => {
    const { manager, children, captureStates } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    children[0]!.say({ type: "capture-rejected", error: "unsupported extension" });
    await vi.advanceTimersByTimeAsync(10);
    expect(captureStates.at(-1)).toMatchObject({
      state: "error",
      error: "unsupported extension",
    });
  });

  it("reports captured hellos", async () => {
    const { manager, children, captured } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    children[0]!.say({
      type: "captured",
      clientHello: "160301aa",
      ja3: "a".repeat(32),
      ja3Text: "771,4865,0,29,0",
      ja4: "t13d0203h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
      capturedAt: "2026-10-03T12:00:00Z",
    });
    await vi.advanceTimersByTimeAsync(10);

    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({ clientHello: "160301aa", ja4: expect.any(String) });
  });

  it("ignores an incomplete captured message", async () => {
    const { manager, children, captured } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    children[0]!.say({ type: "captured", clientHello: "160301aa" });
    await vi.advanceTimersByTimeAsync(10);
    expect(captured).toHaveLength(0);
  });

  it("tolerates partial lines and garbage on stdout", async () => {
    const { manager, children } = setup();
    const started = manager.start();

    // A ready message split across two chunks, with noise around it.
    children[0]!.stdout.emit("data", "not json\n" + '{"type":"ready","port":4242,');
    children[0]!.stdout.emit(
      "data",
      '"token":"abc","profiles":["chrome_150"],"defaultProfile":"chrome_150","version":"1"}\n',
    );
    await started;

    const state = manager.state();
    expect(state.kind).toBe("running");
    if (state.kind === "running") expect(state.port).toBe(4242);
  });

  it("restart() tears the old child down before starting a new one", async () => {
    const { manager, children, spawner } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    const restarted = manager.restart();
    expect(children[0]!.killed).toBe(true);
    children[1]!.readyNow(51236);
    await restarted;

    expect(spawner).toHaveBeenCalledTimes(2);
    expect(manager.endpoint()?.port).toBe(51236);
  });

  it("surfaces a spawn failure as failed rather than throwing", async () => {
    const states: unknown[] = [];
    const manager = new HelperManager({
      exe: "C:/missing.exe",
      spawn: () => {
        throw new Error("ENOENT");
      },
      onState: (s) => states.push(s),
      onCaptured: () => {},
      onCaptureState: () => {},
      log: () => {},
    });

    await expect(manager.start()).resolves.toBeUndefined();
    expect(manager.state().kind).toBe("failed");
  });

  // sendCapture before the child exists must not throw: the UI may toggle it
  // while the helper is restarting.
  it("drops capture commands when there is no child", () => {
    const { manager } = setup();
    expect(() => manager.sendCapture(true, "127.0.0.1:8886", "127.0.0.1:8080")).not.toThrow();
  });

  it("reports helper log lines through the log callback", async () => {
    const { manager, children, logs } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    children[0]!.say({ type: "log", level: "warn", msg: "preamble rejected" });
    await vi.advanceTimersByTimeAsync(10);
    expect(JSON.stringify(logs)).toContain("preamble rejected");
  });
});
