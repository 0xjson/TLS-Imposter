/**
 * Plugin settings: schema, defaults, validation and persistence.
 *
 * This module never touches the helper process and never imports the Caido SDK,
 * which keeps it directly unit-testable.
 */
import { readFile, writeFile, mkdir } from "fs/promises";
import { dirname } from "path";

export type FingerprintSource = "preset" | "captured";

export type CapturedHello = {
  clientHello: string;
  ja3: string;
  ja4: string;
  capturedAt: string;
};

export type Settings = {
  source: FingerprintSource;
  profile: string;
  timeoutSec: number;
  capture: {
    enabled: boolean;
    listen: string;
    forwardTo: string;
    last: CapturedHello | null;
  };
};

export const DEFAULTS: Settings = {
  source: "preset",
  // Matches Caido's own bundled Chromium, which is the browser most traffic
  // through this plugin comes from. Measured, not guessed: that browser's
  // ClientHello yields chrome_146's JA4 exactly (spec 11.3.5). Revisit when
  // Caido ships a newer Chromium — a profile from a *newer* Chrome than the
  // browser sending the headers reintroduces a mismatch.
  profile: "chrome_146",
  timeoutSec: 30,
  capture: {
    enabled: false,
    listen: "127.0.0.1:8886",
    forwardTo: "127.0.0.1:8080",
    last: null,
  },
};

export type ValidateOptions = {
  /** Profile names the helper reported. Empty means "not known yet". */
  profiles: string[];
  fallbackProfile: string;
};

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object | null ? DeepPartial<NonNullable<T[K]>> | null : T[K];
};

const MIN_TIMEOUT = 1;
const MAX_TIMEOUT = 600;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Loopback only: the helper must never be reachable from the network. */
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function splitHostPort(addr: string): { host: string; port: number } | null {
  const match = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(addr);
  if (match === null) return null;
  const host = match[1]!;
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

function validateAddress(
  value: unknown,
  fallback: string,
  field: string,
  warnings: string[],
): string {
  if (typeof value !== "string") return fallback;

  const parts = splitHostPort(value);
  if (parts === null) {
    warnings.push(`${field}: "${value}" is not host:port; using ${fallback}`);
    return fallback;
  }
  if (!LOOPBACK.has(parts.host)) {
    warnings.push(`${field}: "${parts.host}" is not a loopback address; using ${fallback}`);
    return fallback;
  }
  return value;
}

function validateCapturedHello(value: unknown, warnings: string[]): CapturedHello | null {
  if (value === null || value === undefined) return null;
  if (!isRecord(value)) return null;

  const { clientHello, ja3, ja4, capturedAt } = value;
  if (
    typeof clientHello !== "string" ||
    typeof ja3 !== "string" ||
    typeof ja4 !== "string" ||
    typeof capturedAt !== "string"
  ) {
    warnings.push("capture.last: incomplete record; discarded");
    return null;
  }
  if (
    clientHello.length === 0 ||
    clientHello.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(clientHello)
  ) {
    warnings.push("capture.last: clientHello is not hex; discarded");
    return null;
  }
  return { clientHello, ja3, ja4, capturedAt };
}

export function validate(
  raw: unknown,
  opts: ValidateOptions,
): { settings: Settings; warnings: string[] } {
  const warnings: string[] = [];
  const input = isRecord(raw) ? raw : {};
  const captureInput = isRecord(input.capture) ? input.capture : {};

  const source: FingerprintSource =
    input.source === "preset" || input.source === "captured" ? input.source : DEFAULTS.source;

  // The shipped default wins over the helper's, which reports tls-client's
  // library default and so tracks the newest Chrome the library knows. Caido
  // drives its own bundled Chromium, and a fingerprint from a newer Chrome than
  // the browser sending the headers is exactly the inconsistency this plugin
  // exists to remove (spec 11.3.5).
  const preferred = opts.profiles.includes(DEFAULTS.profile)
    ? DEFAULTS.profile
    : opts.fallbackProfile;

  let profile = DEFAULTS.profile;
  if (typeof input.profile === "string" && input.profile !== "") {
    // An empty profile list means the helper has not reported yet; accept the
    // stored value rather than silently rewriting what cannot be checked.
    if (opts.profiles.length === 0 || opts.profiles.includes(input.profile)) {
      profile = input.profile;
    } else {
      warnings.push(`profile: "${input.profile}" is not available; using ${preferred}`);
      profile = preferred;
    }
  } else if (preferred !== "") {
    profile = preferred;
  }

  let timeoutSec = DEFAULTS.timeoutSec;
  if (typeof input.timeoutSec === "number") {
    if (
      Number.isInteger(input.timeoutSec) &&
      input.timeoutSec >= MIN_TIMEOUT &&
      input.timeoutSec <= MAX_TIMEOUT
    ) {
      timeoutSec = input.timeoutSec;
    } else {
      warnings.push(
        `timeoutSec: ${input.timeoutSec} is outside ${MIN_TIMEOUT}-${MAX_TIMEOUT}; ` +
          `using ${DEFAULTS.timeoutSec}`,
      );
    }
  }

  return {
    settings: {
      source,
      profile,
      timeoutSec,
      capture: {
        enabled:
          typeof captureInput.enabled === "boolean"
            ? captureInput.enabled
            : DEFAULTS.capture.enabled,
        listen: validateAddress(
          captureInput.listen,
          DEFAULTS.capture.listen,
          "capture.listen",
          warnings,
        ),
        forwardTo: validateAddress(
          captureInput.forwardTo,
          DEFAULTS.capture.forwardTo,
          "capture.forwardTo",
          warnings,
        ),
        last: validateCapturedHello(captureInput.last, warnings),
      },
    },
    warnings,
  };
}

function merge(base: Settings, patch: DeepPartial<Settings>): unknown {
  const capturePatch = patch.capture ?? {};
  return {
    ...base,
    ...patch,
    capture: { ...base.capture, ...capturePatch },
  };
}

/** Holds the settings in memory and mirrors them to a JSON file. */
export class SettingsStore {
  private settings: Settings = DEFAULTS;

  constructor(private readonly path: string) {}

  /** Reads the file, validating whatever is found. Returns any warnings. */
  async load(opts: ValidateOptions): Promise<string[]> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(this.path, "utf8"));
    } catch (err) {
      const code = (err as { code?: string }).code;
      const { settings } = validate(undefined, opts);
      this.settings = settings;
      if (code === "ENOENT") {
        return [];
      }
      // A corrupt file must not stop the plugin from loading.
      return [`settings file unreadable (${String(err)}); using defaults`];
    }

    const { settings, warnings } = validate(parsed, opts);
    this.settings = settings;
    return warnings;
  }

  get(): Settings {
    return this.settings;
  }

  /** Validates a patch over the current settings, then persists the result. */
  async update(patch: DeepPartial<Settings>, opts: ValidateOptions): Promise<string[]> {
    const { settings, warnings } = validate(merge(this.settings, patch), opts);
    this.settings = settings;
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, JSON.stringify(settings, null, 2), "utf8");
    return warnings;
  }
}
