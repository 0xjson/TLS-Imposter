/**
 * Plugin entrypoint: owns the lifetime of the settings store, the helper
 * process and the 502 fallback responder, and is the only place they meet.
 */
import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";
import { spawn } from "child_process";
import { writeFile } from "fs/promises";
import { join } from "path";

import { openOneShot502 } from "./fallback";
import { HelperManager, type CaptureState, type ChildHandle, type HelperState } from "./helper";
import { enableForAllDomains, readRule, type RoutingState } from "./routing";
import { SettingsStore, type DeepPartial, type Settings } from "./settings";
import { registerUpstream } from "./upstream";

const HELPER_EXE = "awesome-tls-helper.exe";

export type StateDTO = {
  helper: HelperState;
  capture: CaptureState;
  settings: Settings;
  routing: RoutingState;
  warnings: string[];
};

// DefineAPI expects each declared signature to take `sdk: SDK` first and
// strips it for the frontend-facing type; omitting it resolves to the SDK's
// "Your callback must respect the format ..." error string.
export type API = DefineAPI<{
  getState: (sdk: SDK) => StateDTO;
  updateSettings: (sdk: SDK, patch: DeepPartial<Settings>) => Promise<StateDTO>;
  restartHelper: (sdk: SDK) => Promise<StateDTO>;
  clearCapture: (sdk: SDK) => Promise<StateDTO>;
  enableRouting: (sdk: SDK) => Promise<StateDTO>;
}>;

export type BackendEvents = DefineEvents<{
  state: (state: StateDTO) => void;
}>;

/** Adapts Caido's child_process to the ChildHandle the manager expects. */
function spawnHelper(exe: string, commandFile: string): ChildHandle {
  const child = spawn(exe, ["-commands", commandFile], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  return {
    stdout: child.stdout!,
    stderr: child.stderr!,
    on: (event, cb) => child.on(event, cb as never),
    kill: () => {
      child.kill();
    },
    closeStdin: () => {
      child.stdin!.end();
    },
  };
}

export function init(sdk: SDK<API, BackendEvents>) {
  const store = new SettingsStore(join(sdk.meta.path(), "settings.json"));
  let capture: CaptureState = { state: "stopped" };
  // Honest until the read lands: the page must not claim anything about
  // routing before Caido has answered.
  let routing: RoutingState = { kind: "unknown", reason: "not read yet" };
  let warnings: string[] = [];

  const log = (level: "info" | "warn" | "error", msg: string) => {
    if (level === "error") sdk.console.error(msg);
    else if (level === "warn") sdk.console.warn(msg);
    else sdk.console.log(msg);
  };

  const graphql: <T>(
    q: string,
    v?: Record<string, unknown>,
  ) => Promise<{ data?: T; errors?: { message: string }[] }> = (q, v) =>
    // Caido rejects an undefined variables argument with "GraphQL variables
    // must be an object", so a query without variables still needs {}.
    sdk.graphql.execute(q, v ?? {}) as never;

  const validateOptions = () => {
    const state = helper.state();
    const fallbackProfile =
      state.kind === "running" && state.defaultProfile !== ""
        ? state.defaultProfile
        : store.get().profile;
    return { profiles: helper.profiles(), fallbackProfile };
  };

  const snapshot = (): StateDTO => ({
    helper: helper.state(),
    capture,
    settings: store.get(),
    routing,
    warnings,
  });

  const publish = () => {
    try {
      sdk.api.send("state", snapshot());
    } catch (err) {
      log("warn", `Awesome TLS: could not publish state: ${String(err)}`);
    }
  };

  const helper = new HelperManager({
    // caido-dev's asset copier flattens each matched file to its basename, so
    // the binary lands directly in the assets directory rather than under bin/
    // (verified in dist/plugin_package/awesome-tls-backend/assets/).
    exe: join(sdk.meta.assetsPath(), HELPER_EXE),
    // Commands travel through a file, not stdin: Caido's child_process does
    // not deliver writes to a child's stdin (verified against Caido 0.58.3).
    commandFile: join(sdk.meta.path(), "command.json"),
    writeCommand: (path, body) => writeFile(path, body, "utf8"),
    spawn: spawnHelper,
    onState: (state) => {
      if (state.kind === "running") {
        // Re-validate now the real profile list is known, and restore the
        // capture listener across restarts.
        void (async () => {
          warnings = await store.update({}, validateOptions());
          const s = store.get();
          if (s.capture.enabled) {
            helper.sendCapture(true, s.capture.listen, s.capture.forwardTo);
          }
          publish();
        })();
      }
      publish();
    },
    onCaptureState: (state) => {
      capture = state;
      publish();
    },
    onCaptured: (hello) => {
      void (async () => {
        warnings = await store.update({ capture: { last: hello } }, validateOptions());
        publish();
      })();
    },
    log,
  });

  // The deny mechanism is opened per denied request rather than held open.
  // The backend SDK has no unload hook, so a long-lived listener could never
  // be released; one leaked here and appeared to wedge Caido's backend while
  // it was stopping the plugin.
  const openDenial = async (): Promise<number | null> => {
    try {
      const r = await openOneShot502(log);
      return r.port;
    } catch (err) {
      log("error", `Awesome TLS: could not open a 502 responder: ${String(err)}`);
      return null;
    }
  };

  registerUpstream(sdk, {
    helper,
    settings: store,
    openDenial,
    log,
  });

  sdk.api.register("getState", () => snapshot());

  sdk.api.register("updateSettings", async (_sdk: SDK, patch: DeepPartial<Settings>) => {
    const before = store.get();
    warnings = await store.update(patch, validateOptions());
    const after = store.get();

    const captureChanged =
      before.capture.enabled !== after.capture.enabled ||
      before.capture.listen !== after.capture.listen ||
      before.capture.forwardTo !== after.capture.forwardTo;

    if (captureChanged) {
      helper.sendCapture(after.capture.enabled, after.capture.listen, after.capture.forwardTo);
    }
    publish();
    return snapshot();
  });

  sdk.api.register("restartHelper", async () => {
    await helper.restart();
    publish();
    return snapshot();
  });

  sdk.api.register("clearCapture", async () => {
    warnings = await store.update({ capture: { last: null } }, validateOptions());
    publish();
    return snapshot();
  });

  sdk.api.register("enableRouting", async () => {
    try {
      routing = { kind: "rule", rule: await enableForAllDomains(graphql, sdk.meta.id()) };
      warnings = [];
    } catch (err) {
      warnings = [String(err)];
      log("error", String(err));
    }
    publish();
    return snapshot();
  });

  // Boot in independent phases, each guarded.
  //
  // The helper is the critical path, so nothing optional may run before it or
  // be able to prevent it starting: an unguarded failure here leaves the UI
  // reporting "stopped" forever with no explanation.
  void (async () => {
    try {
      warnings = await store.load({ profiles: [], fallbackProfile: store.get().profile });
    } catch (err) {
      warnings = [`settings could not be loaded: ${String(err)}`];
      log("error", `Awesome TLS: ${warnings[0]}`);
    }

    try {
      await helper.start();
    } catch (err) {
      log("error", `Awesome TLS: helper failed to start: ${String(err)}`);
    }
    publish();

    // Routing discovery only populates the status card, but the card reports
    // whether traffic is being routed, so "could not tell" has to reach it as
    // itself rather than as "no rule".
    routing = await readRule(graphql, sdk.meta.id());
    if (routing.kind === "unknown") {
      log("warn", `Awesome TLS: could not read the routing rule: ${routing.reason}`);
    }
    publish();
  })();
}
