/**
 * Supervises the Go helper process and the control protocol spoken over its
 * stdio.
 *
 * The process is injected through `spawn`, so this module is testable without
 * one, and it deliberately knows nothing about settings: the caller decides
 * what to send.
 */
import type { CapturedHello } from "./settings";

export const READY_TIMEOUT_MS = 10_000;
export const BACKOFF_MS = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
export const MAX_FAILURES = 5;
export const FAILURE_WINDOW_MS = 60_000;

export type HelperState =
  | { kind: "starting" }
  | { kind: "running"; port: number; profiles: string[]; defaultProfile: string; version: string }
  | { kind: "restarting"; attempt: number; error: string }
  | { kind: "failed"; error: string }
  | { kind: "stopped" };

export type CaptureState = {
  state: "listening" | "stopped" | "error";
  listen?: string;
  error?: string;
};

/** The subset of a child process this module uses. */
export type ChildHandle = {
  stdout: { on(event: "data", cb: (chunk: unknown) => void): unknown };
  stderr: { on(event: "data", cb: (chunk: unknown) => void): unknown };
  on(event: "exit", cb: (code: number | null) => void): unknown;
  write(line: string): void;
  kill(): void;
  closeStdin(): void;
};

export type HelperOptions = {
  exe: string;
  spawn: (exe: string) => ChildHandle;
  onState: (state: HelperState) => void;
  onCaptured: (hello: CapturedHello) => void;
  onCaptureState: (state: CaptureState) => void;
  log: (level: "info" | "warn" | "error", msg: string) => void;
};

type Endpoint = { port: number; token: string };

export class HelperManager {
  private child: ChildHandle | null = null;
  private current: HelperState = { kind: "stopped" };
  private point: Endpoint | null = null;
  private knownProfiles: string[] = [];
  private stopping = false;
  /** Set while we are killing a child on purpose, so its exit event is not
   * mistaken for a crash and does not trigger the restart path. */
  private intentionalExit = false;
  private buffer = "";
  private lastStderr = "";
  private failures: number[] = [];
  private readyResolve: (() => void) | null = null;
  private readyTimer: ReturnType<typeof setTimeout> | null = null;
  private restartTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly opts: HelperOptions) {}

  state(): HelperState {
    return this.current;
  }

  /**
   * Internal: carries the auth token, so its result must never be published to
   * the frontend or written to a log.
   */
  endpoint(): Endpoint | null {
    return this.point;
  }

  profiles(): string[] {
    return this.knownProfiles;
  }

  async start(): Promise<void> {
    this.stopping = false;
    return this.spawnChild();
  }

  stop(): void {
    this.stopping = true;
    this.clearTimers();
    this.teardown();
    this.setState({ kind: "stopped" });
  }

  async restart(): Promise<void> {
    this.failures = [];
    this.stopping = true;
    this.clearTimers();
    this.teardown();
    this.stopping = false;
    return this.spawnChild();
  }

  sendCapture(enabled: boolean, listen: string, forwardTo: string): void {
    this.send({ type: "capture", enabled, listen, forwardTo });
  }

  /** Closing stdin is the helper's documented shutdown signal; kill is the
   * fallback if it does not take the hint. */
  private teardown(): void {
    if (this.child !== null) {
      const child = this.child;
      // Clear the field first: kill() emits exit synchronously.
      this.child = null;
      this.intentionalExit = true;
      try {
        child.closeStdin();
        child.kill();
      } finally {
        this.intentionalExit = false;
      }
    }
    this.point = null;
  }

  private send(msg: unknown): void {
    if (this.child === null) return;
    try {
      this.child.write(JSON.stringify(msg) + "\n");
    } catch (err) {
      this.opts.log("warn", `helper: write failed: ${String(err)}`);
    }
  }

  private spawnChild(): Promise<void> {
    this.setState({ kind: "starting" });
    this.buffer = "";
    this.lastStderr = "";

    let child: ChildHandle;
    try {
      child = this.opts.spawn(this.opts.exe);
    } catch (err) {
      this.setState({ kind: "failed", error: `spawn failed: ${String(err)}` });
      return Promise.resolve();
    }
    this.child = child;

    child.stdout.on("data", (chunk) => this.onStdout(String(chunk)));
    child.stderr.on("data", (chunk) => {
      this.lastStderr = String(chunk).trim();
      this.opts.log("warn", `helper stderr: ${this.lastStderr}`);
    });
    child.on("exit", (code) => this.onExit(code));

    return new Promise<void>((resolve) => {
      this.readyResolve = resolve;
      this.readyTimer = setTimeout(() => {
        this.readyTimer = null;
        if (this.current.kind !== "running") {
          this.setState({
            kind: "failed",
            error: this.lastStderr || `no ready message within ${READY_TIMEOUT_MS}ms`,
          });
          this.teardown();
        }
        this.resolveReady();
      }, READY_TIMEOUT_MS);
    });
  }

  private resolveReady(): void {
    const resolve = this.readyResolve;
    this.readyResolve = null;
    if (this.readyTimer !== null) {
      clearTimeout(this.readyTimer);
      this.readyTimer = null;
    }
    resolve?.();
  }

  private onStdout(chunk: string): void {
    this.buffer += chunk;
    // The helper writes one JSON object per line, but a chunk may split a line.
    for (;;) {
      const nl = this.buffer.indexOf("\n");
      if (nl < 0) break;
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (line === "") continue;

      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue; // a garbled line must not take the plugin down
      }
      this.dispatch(msg);
    }
  }

  private dispatch(msg: Record<string, unknown>): void {
    switch (msg.type) {
      case "ready": {
        const port = typeof msg.port === "number" ? msg.port : 0;
        const token = typeof msg.token === "string" ? msg.token : "";
        if (port <= 0 || token === "") {
          this.setState({ kind: "failed", error: "helper sent an unusable ready message" });
          this.teardown();
          this.resolveReady();
          return;
        }
        const profiles = Array.isArray(msg.profiles)
          ? msg.profiles.filter((p): p is string => typeof p === "string")
          : [];
        this.knownProfiles = profiles;
        this.point = { port, token };
        this.setState({
          kind: "running",
          port,
          profiles,
          defaultProfile: typeof msg.defaultProfile === "string" ? msg.defaultProfile : "",
          version: typeof msg.version === "string" ? msg.version : "",
        });
        this.resolveReady();
        return;
      }
      case "capture-status":
        this.opts.onCaptureState({
          state: msg.state === "listening" || msg.state === "error" ? msg.state : "stopped",
          listen: typeof msg.listen === "string" ? msg.listen : undefined,
          error: typeof msg.error === "string" ? msg.error : undefined,
        });
        return;
      case "captured": {
        const { clientHello, ja3, ja4, capturedAt } = msg;
        if (
          typeof clientHello === "string" &&
          typeof ja3 === "string" &&
          typeof ja4 === "string" &&
          typeof capturedAt === "string"
        ) {
          this.opts.onCaptured({ clientHello, ja3, ja4, capturedAt });
        }
        return;
      }
      case "capture-rejected":
        this.opts.onCaptureState({
          state: "error",
          error: typeof msg.error === "string" ? msg.error : "captured hello was unusable",
        });
        return;
      case "log":
        this.opts.log(
          msg.level === "error" ? "error" : msg.level === "warn" ? "warn" : "info",
          `helper: ${String(msg.msg ?? "")}`,
        );
        return;
      default:
        return;
    }
  }

  private onExit(code: number | null): void {
    this.child = null;
    // Withdraw the endpoint at once: a request routed to a dead helper would
    // hang, and the fallback responder should take over instead.
    this.point = null;
    this.resolveReady();

    // A child we killed on purpose is not a crash. Without this, tearing down
    // after a ready-timeout would immediately look like an unexpected exit and
    // start a restart cycle on top of the failure we just reported.
    if (this.stopping || this.intentionalExit) return;

    const error = this.lastStderr || `helper exited with code ${String(code)}`;

    const now = Date.now();
    this.failures = this.failures.filter((t) => now - t < FAILURE_WINDOW_MS);
    this.failures.push(now);

    if (this.failures.length > MAX_FAILURES) {
      this.setState({
        kind: "failed",
        error: `${error} (gave up after ${this.failures.length} failures)`,
      });
      return;
    }

    const attempt = this.failures.length;
    const delay = BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)]!;
    this.setState({ kind: "restarting", attempt, error });

    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      if (!this.stopping) void this.spawnChild();
    }, delay);
  }

  private clearTimers(): void {
    if (this.restartTimer !== null) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }
    if (this.readyTimer !== null) {
      clearTimeout(this.readyTimer);
      this.readyTimer = null;
    }
  }

  private setState(state: HelperState): void {
    this.current = state;
    this.opts.onState(state);
  }
}
