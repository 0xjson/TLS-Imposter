/**
 * Plugin entrypoint: owns the lifetime of the settings store, the helper
 * process and the 502 fallback responder, and is the only place they meet.
 */
import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";
import { spawn } from "child_process";
import { join } from "path";

import { startFallbackResponder, type FallbackResponder } from "./fallback";
import { HelperManager, type CaptureState, type ChildHandle, type HelperState } from "./helper";
import { enableForAllDomains, findBackendPluginId, readRule, type UpstreamRule } from "./routing";
import { SettingsStore, type DeepPartial, type Settings } from "./settings";
import { registerUpstream } from "./upstream";

const HELPER_EXE = "awesome-tls-helper.exe";

export type StateDTO = {
  helper: HelperState;
  capture: CaptureState;
  settings: Settings;
  routing: UpstreamRule | null;
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
function spawnHelper(exe: string): ChildHandle {
  const child = spawn(exe, { stdio: ["pipe", "pipe", "pipe"] });
  return {
    stdout: child.stdout!,
    stderr: child.stderr!,
    on: (event, cb) => child.on(event, cb as never),
    write: (line) => {
      child.stdin!.write(line);
    },
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
  let routing: UpstreamRule | null = null;
  let warnings: string[] = [];
  let fallback: FallbackResponder | null = null;

  const log = (level: "info" | "warn" | "error", msg: string) => {
    if (level === "error") sdk.console.error(msg);
    else if (level === "warn") sdk.console.warn(msg);
    else sdk.console.log(msg);
  };

  const graphql: <T>(
    q: string,
    v?: Record<string, unknown>,
  ) => Promise<{ data?: T; errors?: { message: string }[] }> = (q, v) =>
    sdk.graphql.execute(q, v) as never;

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

  // The deny mechanism must exist before the hook is registered, or an early
  // request arriving while the helper is still starting has nothing to be
  // denied by.
  void startFallbackResponder(log)
    .then((r) => {
      fallback = r;
      log("info", `Awesome TLS: 502 responder on 127.0.0.1:${r.port}`);
    })
    .catch((err) => {
      log("error", `Awesome TLS: no 502 responder: ${String(err)}`);
    });

  registerUpstream(sdk, {
    helper,
    settings: store,
    fallbackPort: () => fallback?.port ?? null,
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
      routing = await enableForAllDomains(graphql, sdk.meta.id());
      warnings = [];
    } catch (err) {
      warnings = [String(err)];
      log("error", String(err));
    }
    publish();
    return snapshot();
  });

  // Boot: settings first so the hook has something to read, then the helper.
  void (async () => {
    warnings = await store.load({ profiles: [], fallbackProfile: store.get().profile });

    const pluginId = await findBackendPluginId(graphql, sdk.meta.id());
    if (pluginId !== null) {
      routing = await readRule(graphql, pluginId);
    }

    await helper.start();
    publish();
  })();
}
