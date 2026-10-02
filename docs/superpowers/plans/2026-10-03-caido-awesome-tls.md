# Caido Awesome TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Caido plugin that makes Caido's outbound HTTPS requests carry a real browser's TLS (JA3/JA4) and HTTP/2 fingerprint, so authorized testing of WAF-protected targets reflects browser behavior.

**Architecture:** A backend plugin registers `sdk.events.onUpstream`, and for each routed request hands Caido a loopback TCP connection to a bundled Go helper, prefixed with an out-of-band preamble naming the real target and fingerprint settings. The helper parses the HTTP/1.1 request Caido writes, re-sends it through `bogdanfinn/tls-client` with the selected browser profile, and writes the response back as buffered HTTP/1.1. A second helper listener optionally sits between the browser and Caido to capture the browser's own ClientHello.

**Tech Stack:** Go 1.26 (`bogdanfinn/tls-client` v1.16.0, `bogdanfinn/utls` v1.7.8-barnius, `bogdanfinn/fhttp` v0.6.9); TypeScript on Caido's QuickJS backend runtime (`@caido/sdk-backend` 0.58.3); Vue 3 + PrimeVue frontend (`@caido/sdk-frontend` 0.58.3); pnpm workspaces; `@caido-community/dev` 0.1.7 for packaging.

**Spec:** `docs/superpowers/specs/2026-10-03-caido-awesome-tls-design.md`

## Global Constraints

- Caido **>= 0.55.0**. `sdk.events.onUpstream` does not exist below it.
- Target platform **Windows x64 only**. The helper is cross-compiled from WSL with `GOOS=windows GOARCH=amd64`.
- Helper link flags are exactly `-trimpath -ldflags "-s -w -H windowsgui"`. `-H windowsgui` prevents a console window from flashing on every spawn.
- Both helper listeners bind **loopback only**. The forward listener binds port `0` and reports the kernel-assigned port.
- Every forward connection is authenticated by a 32-byte random token generated at helper startup. Comparison uses `crypto/subtle.ConstantTimeCompare`. **The token must never appear in any log line, any `log` control message, or any value reachable from the frontend.**
- `tls-client` options are fixed at: `WithNotFollowRedirects()`, `WithInsecureSkipVerify()`, `WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true})`, `WithTimeoutSeconds(cfg.TimeoutSec)`. No cookie jar: construct with `tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)`, never a convenience constructor that attaches one.
- `DisableCompression: true` is load-bearing, not an optimization. `fhttp` decompresses whenever the *caller's* `Accept-Encoding` mentions gzip (`transport.go:2571`) and unconditionally on HTTP/2 (`h2_bundle.go:9273`). Without it the helper returns a decompressed body still labelled `Content-Encoding: gzip`.
- Responses are **buffered**, never streamed. Decided at design review.
- Request bodies are capped at 256 MiB; the preamble line at 64 KiB.
- Fail closed: when the helper is unavailable the `onUpstream` callback throws so the request fails. Never fall back to Caido's own stack, which would silently send the operator's real fingerprint.
- Header order reaches `tls-client` through `fhttp.HeaderOrderKey` **lowercased** — the library matches case-sensitively and ignores mixed-case entries.
- Plugin package id `awesome-tls`; backend component id `awesome-tls-backend`; frontend component id `awesome-tls-frontend`.

## Review Focus

Five input classes the spec implies, each with the test that pins it placed in the task that owns the code:

1. **`Host` header disagreeing with the connection target.** Caido may write an absolute-form request-target or a rewritten `Host`. The helper must dial the preamble's target regardless and leave `Host` untouched. → Task 8.
2. **Response with neither `Content-Length` nor `Transfer-Encoding`** (HTTP/1.0 connection-close framing). Reading must terminate at EOF and still produce an exact `Content-Length`, not hang. → Task 9.
3. **Bodiless responses: `HEAD`, 204, 304.** A computed `Content-Length` must not cause a body to be written, or the client desyncs. → Task 5.
4. **A second request on the same connection after an error response.** After a 502/504 the connection must either stay correctly framed for the next request or be closed deliberately — never left half-written. → Task 9.
5. **Capture listener receiving plaintext HTTP** (browser proxying a non-TLS site). The sniffer must relay bytes normally and never block the connection waiting for a ClientHello that will not arrive. → Task 11.

---

## File Structure

```
caido-awesome-tls/
  caido.config.ts                     # package + component ids, backend assets glob
  package.json                        # workspace root: build, test, typecheck scripts
  pnpm-workspace.yaml
  .gitignore                          # packages/backend/assets/bin/, dist/
  helper/
    go.mod  go.sum
    cmd/awesome-tls-helper/main.go    # flag parsing, wiring, shutdown
    internal/control/control.go       # JSON-lines protocol types, Writer, ReadCommands
    internal/control/control_test.go
    internal/preamble/preamble.go     # Magic, Config, Read, Validate
    internal/preamble/preamble_test.go
    internal/httpwire/request.go      # ReadRequest, Request, Header
    internal/httpwire/request_test.go
    internal/httpwire/response.go     # WriteResponse, WriteError
    internal/httpwire/response_test.go
    internal/fingerprint/spec.go      # SpecFromRaw/Hex, ECH + PSK handling
    internal/fingerprint/spec_test.go
    internal/fingerprint/profiles.go  # Profiles, Default, Lookup, Custom
    internal/fingerprint/profiles_test.go
    internal/fingerprint/ja.go        # JA3, JA4
    internal/fingerprint/ja_test.go
    internal/fingerprint/testdata/    # recorded ClientHellos
    internal/forward/cache.go         # client cache keyed by profile+hello+timeout
    internal/forward/cache_test.go
    internal/forward/forward.go       # Handle: keep-alive loop, send, respond
    internal/forward/forward_test.go
    internal/relay/relay.go           # Upgrade/WebSocket byte relay
    internal/relay/relay_test.go
    internal/capture/sniff.go         # SniffClientHello over a TeeReader
    internal/capture/sniff_test.go
    internal/capture/listener.go      # capture listener lifecycle
    internal/capture/listener_test.go
  packages/backend/
    package.json
    src/index.ts                      # init(): wiring, RPC registration
    src/settings.ts                   # Settings type, DEFAULTS, validate, SettingsStore
    src/settings.test.ts
    src/helper.ts                     # HelperManager: spawn, ready, backoff, stop
    src/helper.test.ts
    src/preamble.ts                   # buildPreamble
    src/preamble.test.ts
    src/upstream.ts                   # registerUpstream
    src/routing.ts                    # GraphQL: read/create/update the upstream rule
    assets/bin/awesome-tls-helper.exe # build output, gitignored
  packages/frontend/
    package.json
    src/index.ts                      # page + sidebar registration, RPC plumbing
    src/App.vue
    src/components/StatusCard.vue
    src/components/FingerprintCard.vue
    src/components/CaptureCard.vue
  docs/superpowers/{specs,plans}/
```

Boundaries worth stating, because they are what keep the files small: `httpwire` knows HTTP framing and nothing about TLS; `fingerprint` knows TLS and nothing about HTTP; `forward` composes the two and owns the only network client; `control` is pure serialization with no knowledge of what the messages mean. In the backend, `settings.ts` never touches the process and `helper.ts` never interprets settings — `index.ts` is the only place they meet.

---

## Phase 0 — Probe Caido's actual behavior

### Task 1: Scaffold the repo and answer the probe questions

Spec section 11.1. The probe plugin is **throwaway**: its findings are written into the spec and its code is deleted at the end of this task. Nothing else in the plan may start until probe question 4 is answered, because a `false` answer changes the design.

**Files:**
- Create: `package.json`, `pnpm-workspace.yaml`, `caido.config.ts`, `.gitignore`
- Create: `packages/backend/package.json`, `packages/backend/src/index.ts` (probe version, deleted in step 8)
- Create: `packages/frontend/package.json`, `packages/frontend/src/index.ts` (stub)
- Modify: `docs/superpowers/specs/2026-10-03-caido-awesome-tls-design.md` (record findings)

**Interfaces:**
- Consumes: nothing.
- Produces: a buildable plugin package (`pnpm build` yields `dist/plugin_package.zip`); recorded answers to probe questions 1-8 in the spec.

- [ ] **Step 1: Create the workspace root**

`package.json`:
```json
{
  "name": "caido-awesome-tls",
  "private": true,
  "version": "0.1.0",
  "scripts": {
    "build:helper": "cd helper && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags \"-s -w -H windowsgui\" -o ../packages/backend/assets/bin/awesome-tls-helper.exe ./cmd/awesome-tls-helper",
    "build": "pnpm build:helper && caido-dev build",
    "test:helper": "cd helper && go test ./...",
    "test:backend": "pnpm -C packages/backend test",
    "test": "pnpm test:helper && pnpm test:backend",
    "typecheck": "pnpm -r typecheck"
  },
  "devDependencies": {
    "@caido-community/dev": "0.1.7",
    "typescript": "^5.6.0"
  }
}
```

`pnpm-workspace.yaml`:
```yaml
packages:
  - "packages/*"
```

`.gitignore`:
```
node_modules/
dist/
packages/backend/assets/bin/
helper/awesome-tls-helper*
```

- [ ] **Step 2: Create `caido.config.ts`**

```ts
import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "awesome-tls",
  name: "Awesome TLS",
  description: "Spoof browser TLS and HTTP/2 fingerprints for Caido traffic",
  version: "0.1.0",
  author: { name: "json" },
  plugins: [
    {
      kind: "backend",
      id: "awesome-tls-backend",
      root: "packages/backend",
      assets: ["./assets/bin/*"],
    },
    {
      kind: "frontend",
      id: "awesome-tls-frontend",
      root: "packages/frontend",
      backend: { id: "awesome-tls-backend" },
    },
  ],
});
```

- [ ] **Step 3: Write the probe backend**

`packages/backend/package.json`:
```json
{
  "name": "awesome-tls-backend",
  "version": "0.1.0",
  "type": "module",
  "main": "src/index.ts",
  "scripts": { "typecheck": "tsc --noEmit", "test": "vitest run" },
  "devDependencies": {
    "@caido/sdk-backend": "0.58.3",
    "@caido/quickjs-types": "0.26.0",
    "typescript": "^5.6.0",
    "vitest": "^2.1.0"
  }
}
```

`packages/backend/src/index.ts` — probe version:
```ts
import type { SDK, DefineAPI } from "caido:plugin";
import type { RequestSpecRaw } from "caido:utils";
import { createServer } from "net";

export type API = DefineAPI<{}>;

export function init(sdk: SDK<API>) {
  // Echo server: logs exactly what Caido writes, then answers 200.
  const srv = createServer((sock) => {
    sdk.console.log("[probe] connection opened");
    let seen = Buffer.alloc(0);
    sock.on("data", (d: Buffer) => {
      seen = Buffer.concat([seen, d]);
      sdk.console.log(`[probe] bytes=${seen.length} text=${JSON.stringify(seen.toString("utf8"))}`);
      if (seen.includes("\r\n\r\n")) {
        sock.write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nprobe");
        seen = Buffer.alloc(0);
      }
    });
    sock.on("close", () => sdk.console.log("[probe] connection closed"));
  });
  srv.listen(0, "127.0.0.1", () => {
    const addr = srv.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    sdk.console.log(`[probe] listening on 127.0.0.1:${port}`);

    sdk.events.onUpstream(async (sdk, request: RequestSpecRaw) => {
      const info = request.getInfo();
      sdk.console.log(
        `[probe] onUpstream host=${info.host} port=${info.port} tls=${info.tls} sni=${info.sni} ` +
        `raw=${JSON.stringify(new TextDecoder().decode(request.getRaw()).slice(0, 200))}`,
      );
      if (info.host === "throw.probe.invalid") {
        throw new Error("[probe] deliberate throw");
      }
      const conn = await sdk.net.connect(`tcp://127.0.0.1:${port}`);
      await conn.send(new TextEncoder().encode("PREAMBLE-MARKER\n"));
      return { connection: conn };
    });
  });
}
```

Note: `sdk.net.connect` takes a URL string or `ConnectionInfo`. If `tcp://` is rejected, try `ConnectionInfo` with `tls = false`; record which form works — Task 15 depends on it.

- [ ] **Step 4: Build and install**

Run: `pnpm install && pnpm build`
Expected: `dist/plugin_package.zip` exists. The helper build step will fail until `helper/` exists — for this task only, run `pnpm exec caido-dev build` directly instead of `pnpm build`.

Then in Caido on Windows: Plugins → Install from file → select the zip. Enable both components.

- [ ] **Step 5: Create the routing rule and exercise the probe**

In Caido: Settings → Upstream → Upstream Plugins → add a rule for `awesome-tls-backend` with allowlist `*`, enabled.

Then, watching Caido's backend log:
1. Replay `GET https://example.com/` — record whether the logged `raw` is HTTP/1.1, whether `PREAMBLE-MARKER` arrives before it (probe questions 1, 2).
2. Replay the same request twice on one Replay session — record whether a second request arrives on the same socket (question 3).
3. Replay `GET https://throw.probe.invalid/` — **record whether the request fails or Caido sends it itself** (question 4).
4. Open a WebSocket target through the proxy (question 5).
5. Send one request each from Proxy, Replay and Automate (question 6).
6. Disable the plugin and check with `tasklist.exe` that nothing lingers; confirm a `-H windowsgui` Go binary still gets working pipes (question 7, revisit in Task 12).
7. Confirm `*` matched every domain (question 8).

- [ ] **Step 6: Record the findings in the spec**

Append a `### 11.1.1 Probe results (2026-10-03)` subsection to the spec, one line per question with the observed answer.

- [ ] **Step 7: Gate on question 4**

If a thrown callback causes Caido to send the request itself, **stop**. Fail-closed is unachievable; report to the user and revise spec section 10 before continuing.

- [ ] **Step 8: Delete the probe and commit the scaffold**

Replace `packages/backend/src/index.ts` with:
```ts
import type { SDK, DefineAPI } from "caido:plugin";

export type API = DefineAPI<{}>;

export function init(_sdk: SDK<API>) {
  // Implemented in Phase 2.
}
```

```bash
git add -A
git commit -m "chore: scaffold plugin package, record Caido upstream probe results"
```

---

## Phase 1 — Go helper

### Task 2: Go module and control channel

**Files:**
- Create: `helper/go.mod`, `helper/internal/control/control.go`
- Test: `helper/internal/control/control_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `control.Ready{Type, Port int, Token, Profiles []string, DefaultProfile, Version string}`
  - `control.CaptureStatus{Type, State, Listen, Error string}`
  - `control.Captured{Type, ClientHello, JA3, JA3Text, JA4, CapturedAt string}`
  - `control.CaptureRejected{Type, Error, JA4 string}`
  - `control.LogMsg{Type, Level, Msg string}`
  - `control.Command{Type, Enabled bool, Listen, ForwardTo string}`
  - `control.NewWriter(io.Writer) *Writer`, `(*Writer).Emit(any) error`, `(*Writer).Logf(level, format string, args ...any)`
  - `control.ReadCommands(io.Reader, func(Command)) error` — returns nil at EOF

- [ ] **Step 1: Initialize the module**

```bash
cd helper
go mod init github.com/json/caido-awesome-tls/helper
go mod edit -go=1.26
```

- [ ] **Step 2: Write the failing test**

`helper/internal/control/control_test.go`:
```go
package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestWriterEmitsOneJSONLinePerMessage(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.Emit(Ready{Type: "ready", Port: 1234, Token: "abc", Profiles: []string{"chrome_150"}, DefaultProfile: "chrome_150", Version: "test"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	w.Logf("info", "hello %d", 7)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}

	var ready Ready
	if err := json.Unmarshal([]byte(lines[0]), &ready); err != nil {
		t.Fatalf("line 0 not JSON: %v", err)
	}
	if ready.Port != 1234 || ready.Type != "ready" {
		t.Errorf("got %+v", ready)
	}

	var lm LogMsg
	if err := json.Unmarshal([]byte(lines[1]), &lm); err != nil {
		t.Fatalf("line 1 not JSON: %v", err)
	}
	if lm.Type != "log" || lm.Level != "info" || lm.Msg != "hello 7" {
		t.Errorf("got %+v", lm)
	}
}

func TestWriterIsConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.Logf("info", "x") }()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("want 50 intact lines, got %d", len(lines))
	}
	for i, l := range lines {
		var lm LogMsg
		if err := json.Unmarshal([]byte(l), &lm); err != nil {
			t.Fatalf("line %d corrupted: %q", i, l)
		}
	}
}

func TestReadCommandsStopsAtEOFAndSkipsGarbage(t *testing.T) {
	in := strings.NewReader(
		`{"type":"capture","enabled":true,"listen":"127.0.0.1:8886","forwardTo":"127.0.0.1:8080"}` + "\n" +
			"not json\n" +
			`{"type":"capture","enabled":false}` + "\n")

	var got []Command
	if err := ReadCommands(in, func(c Command) { got = append(got, c) }); err != nil {
		t.Fatalf("ReadCommands: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 commands, got %d", len(got))
	}
	if !got[0].Enabled || got[0].Listen != "127.0.0.1:8886" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Enabled {
		t.Errorf("got[1] = %+v", got[1])
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd helper && go test ./internal/control/`
Expected: build failure — `undefined: NewWriter`, `undefined: Ready`.

- [ ] **Step 4: Write the implementation**

`helper/internal/control/control.go`:
```go
// Package control is the JSON-lines protocol spoken over the helper's stdio.
// It is pure serialization: it does not know what any message means.
package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type Ready struct {
	Type           string   `json:"type"`
	Port           int      `json:"port"`
	Token          string   `json:"token"`
	Profiles       []string `json:"profiles"`
	DefaultProfile string   `json:"defaultProfile"`
	Version        string   `json:"version"`
}

type CaptureStatus struct {
	Type   string `json:"type"`
	State  string `json:"state"` // listening | stopped | error
	Listen string `json:"listen,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Captured struct {
	Type        string `json:"type"`
	ClientHello string `json:"clientHello"`
	JA3         string `json:"ja3"`
	JA3Text     string `json:"ja3Text"`
	JA4         string `json:"ja4"`
	CapturedAt  string `json:"capturedAt"`
}

type CaptureRejected struct {
	Type  string `json:"type"`
	Error string `json:"error"`
	JA4   string `json:"ja4,omitempty"`
}

type LogMsg struct {
	Type  string `json:"type"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type Command struct {
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	Listen    string `json:"listen"`
	ForwardTo string `json:"forwardTo"`
}

// Writer serializes messages to a stream, one JSON object per line.
// Emit is safe for concurrent use; lines never interleave.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (w *Writer) Emit(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(b)
	return err
}

// Logf emits a diagnostic. Callers must never pass the auth token.
func (w *Writer) Logf(level, format string, args ...any) {
	_ = w.Emit(LogMsg{Type: "log", Level: level, Msg: fmt.Sprintf(format, args...)})
}

// ReadCommands consumes commands until EOF, which is the shutdown signal.
// Unparseable lines are skipped rather than fatal, so a protocol slip on one
// line cannot take the helper down.
func ReadCommands(r io.Reader, fn func(Command)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var c Command
		if err := json.Unmarshal(line, &c); err != nil {
			continue
		}
		fn(c)
	}
	return sc.Err()
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd helper && go test ./internal/control/ -v`
Expected: all three tests PASS.

- [ ] **Step 6: Commit**

```bash
git add helper/go.mod helper/internal/control/
git commit -m "feat(helper): JSON-lines control protocol over stdio"
```

---

### Task 3: Connection preamble

**Files:**
- Create: `helper/internal/preamble/preamble.go`
- Test: `helper/internal/preamble/preamble_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `preamble.Magic = "AWESOMETLS/1 "`, `preamble.MaxLineLen = 64 * 1024`
  - `preamble.Target{Host string, Port int, TLS bool}`
  - `preamble.Config{Token string, Target Target, SNI *string, Profile string, ClientHello string, TimeoutSec int}`
  - `preamble.Read(*bufio.Reader) (*Config, error)`
  - `(*Config).Validate(expectedToken string) error`
  - `(*Config).Addr() string`, `(*Config).ServerName() string`

- [ ] **Step 1: Write the failing test**

`helper/internal/preamble/preamble_test.go`:
```go
package preamble

import (
	"bufio"
	"strings"
	"testing"
)

const tok = "0123456789abcdef"

func read(t *testing.T, s string) (*Config, error) {
	t.Helper()
	return Read(bufio.NewReader(strings.NewReader(s)))
}

func TestReadParsesConfigAndLeavesRemainderIntact(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(
		Magic + `{"token":"` + tok + `","target":{"host":"example.com","port":443,"tls":true},` +
			`"sni":null,"profile":"chrome_150","clientHello":null,"timeoutSec":30}` + "\n" +
			"GET / HTTP/1.1\r\n\r\n"))

	cfg, err := Read(br)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg.Target.Host != "example.com" || cfg.Target.Port != 443 || !cfg.Target.TLS {
		t.Errorf("target = %+v", cfg.Target)
	}
	if cfg.Profile != "chrome_150" || cfg.TimeoutSec != 30 {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.SNI != nil {
		t.Errorf("SNI = %v, want nil", *cfg.SNI)
	}
	rest, _ := br.ReadString('\n')
	if rest != "GET / HTTP/1.1\r\n" {
		t.Errorf("remainder = %q; the request must be left for the HTTP reader", rest)
	}
}

func TestReadRejectsBadMagicAndOverlongLine(t *testing.T) {
	if _, err := read(t, "GET / HTTP/1.1\r\n\r\n"); err == nil {
		t.Error("want error for missing magic")
	}
	long := Magic + "{" + strings.Repeat("x", MaxLineLen) + "}\n"
	if _, err := read(t, long); err == nil {
		t.Error("want error for overlong preamble line")
	}
}

func TestValidateChecksTokenAndFields(t *testing.T) {
	base := func() *Config {
		return &Config{
			Token:      tok,
			Target:     Target{Host: "example.com", Port: 443, TLS: true},
			Profile:    "chrome_150",
			TimeoutSec: 30,
		}
	}
	if err := base().Validate(tok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]func(*Config){
		"wrong token": func(c *Config) { c.Token = "deadbeef" },
		"empty host":  func(c *Config) { c.Target.Host = "" },
		"port zero":   func(c *Config) { c.Target.Port = 0 },
		"port high":   func(c *Config) { c.Target.Port = 70000 },
		"no profile":  func(c *Config) { c.Profile = "" },
		"timeout 0":   func(c *Config) { c.TimeoutSec = 0 },
		"bad hex":     func(c *Config) { c.ClientHello = "nothex" },
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if err := c.Validate(tok); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestAddrAndServerName(t *testing.T) {
	c := &Config{Target: Target{Host: "example.com", Port: 8443, TLS: true}}
	if got := c.Addr(); got != "example.com:8443" {
		t.Errorf("Addr = %q", got)
	}
	if got := c.ServerName(); got != "example.com" {
		t.Errorf("ServerName = %q", got)
	}

	sni := "override.test"
	c.SNI = &sni
	if got := c.ServerName(); got != "override.test" {
		t.Errorf("ServerName with override = %q", got)
	}

	ip := &Config{Target: Target{Host: "93.184.216.34", Port: 443, TLS: true}}
	if got := ip.ServerName(); got != "" {
		t.Errorf("ServerName for IP literal = %q, want empty (no SNI for IPs)", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd helper && go test ./internal/preamble/`
Expected: build failure — `undefined: Read`, `undefined: Config`.

- [ ] **Step 3: Write the implementation**

`helper/internal/preamble/preamble.go`:
```go
// Package preamble parses the out-of-band configuration line the plugin writes
// at the start of every forward connection.
package preamble

import (
	"bufio"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	Magic      = "AWESOMETLS/1 "
	MaxLineLen = 64 * 1024
)

type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	TLS  bool   `json:"tls"`
}

type Config struct {
	Token       string  `json:"token"`
	Target      Target  `json:"target"`
	SNI         *string `json:"sni"`
	Profile     string  `json:"profile"`
	ClientHello string  `json:"clientHello"`
	TimeoutSec  int     `json:"timeoutSec"`
}

// Read consumes exactly one preamble line and leaves everything after the
// terminating newline in the reader for the HTTP layer.
func Read(br *bufio.Reader) (*Config, error) {
	prefix, err := br.Peek(len(Magic))
	if err != nil {
		return nil, fmt.Errorf("read preamble: %w", err)
	}
	if string(prefix) != Magic {
		return nil, errors.New("read preamble: bad magic")
	}
	if _, err := br.Discard(len(Magic)); err != nil {
		return nil, err
	}

	line := make([]byte, 0, 512)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read preamble: %w", err)
		}
		if b == '\n' {
			break
		}
		if len(line) >= MaxLineLen {
			return nil, fmt.Errorf("read preamble: line exceeds %d bytes", MaxLineLen)
		}
		line = append(line, b)
	}

	var cfg Config
	if err := json.Unmarshal(line, &cfg); err != nil {
		return nil, fmt.Errorf("read preamble: %w", err)
	}
	return &cfg, nil
}

// Validate authenticates the caller and rejects configurations the forwarder
// could not act on.
func (c *Config) Validate(expectedToken string) error {
	if subtle.ConstantTimeCompare([]byte(c.Token), []byte(expectedToken)) != 1 {
		return errors.New("preamble: token mismatch")
	}
	if strings.TrimSpace(c.Target.Host) == "" {
		return errors.New("preamble: empty target host")
	}
	if c.Target.Port < 1 || c.Target.Port > 65535 {
		return fmt.Errorf("preamble: port %d out of range", c.Target.Port)
	}
	if c.Profile == "" {
		return errors.New("preamble: empty profile")
	}
	if c.TimeoutSec < 1 || c.TimeoutSec > 600 {
		return fmt.Errorf("preamble: timeoutSec %d out of range", c.TimeoutSec)
	}
	if c.ClientHello != "" {
		if _, err := hex.DecodeString(c.ClientHello); err != nil {
			return fmt.Errorf("preamble: clientHello is not hex: %w", err)
		}
	}
	return nil
}

func (c *Config) Addr() string {
	return net.JoinHostPort(c.Target.Host, strconv.Itoa(c.Target.Port))
}

// ServerName is the SNI to present: the override when given, otherwise the
// target host, and empty for IP literals, which must not carry SNI.
func (c *Config) ServerName() string {
	if c.SNI != nil {
		return *c.SNI
	}
	if net.ParseIP(c.Target.Host) != nil {
		return ""
	}
	return c.Target.Host
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd helper && go test ./internal/preamble/ -v`
Expected: all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add helper/internal/preamble/
git commit -m "feat(helper): parse and authenticate the connection preamble"
```

---

### Task 4: HTTP/1.1 request parsing

Preserves what Go's `net/http` throws away: header order, header casing, duplicate headers, and the
request-target exactly as written.

**Files:**
- Create: `helper/internal/httpwire/request.go`
- Test: `helper/internal/httpwire/request_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `httpwire.Header{Name, Value string}`
  - `httpwire.Request{Method, Target, Proto string, Headers []Header, Body []byte, IsUpgrade bool, Head []byte}`
  - `httpwire.ReadRequest(*bufio.Reader) (*Request, error)`
  - `(*Request).Get(name string) string` — case-insensitive, first match, `""` if absent
  - `(*Request).OrderedNames() []string` — header names in wire order, lowercased
  - `httpwire.MaxBodyBytes = 256 << 20`
  - `httpwire.ErrBodyTooLarge`

- [ ] **Step 1: Write the failing test**

`helper/internal/httpwire/request_test.go`:
```go
package httpwire

import (
	"bufio"
	"strings"
	"testing"
)

func parse(t *testing.T, raw string) *Request {
	t.Helper()
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest(%q): %v", raw, err)
	}
	return req
}

func TestPreservesHeaderOrderCasingAndDuplicates(t *testing.T) {
	req := parse(t, "GET /x HTTP/1.1\r\n"+
		"Host: example.com\r\n"+
		"X-Weird-CASE: 1\r\n"+
		"Cookie: a=1\r\n"+
		"cookie: b=2\r\n"+
		"Accept: */*\r\n"+
		"\r\n")

	want := []Header{
		{"Host", "example.com"},
		{"X-Weird-CASE", "1"},
		{"Cookie", "a=1"},
		{"cookie", "b=2"},
		{"Accept", "*/*"},
	}
	if len(req.Headers) != len(want) {
		t.Fatalf("got %d headers, want %d: %+v", len(req.Headers), len(want), req.Headers)
	}
	for i := range want {
		if req.Headers[i] != want[i] {
			t.Errorf("header %d = %+v, want %+v", i, req.Headers[i], want[i])
		}
	}

	if got := req.Get("COOKIE"); got != "a=1" {
		t.Errorf("Get is case-insensitive and first-match: got %q", got)
	}
	if got := req.Get("absent"); got != "" {
		t.Errorf("Get(absent) = %q, want empty", got)
	}
}

func TestKeepsRequestTargetVerbatim(t *testing.T) {
	// Encoded slash, double slash, and a literal space-free odd path must survive untouched.
	req := parse(t, "GET /a%2Fb//c?q=1%20%2B2&r=%2f HTTP/1.1\r\nHost: h\r\n\r\n")
	if req.Target != "/a%2Fb//c?q=1%20%2B2&r=%2f" {
		t.Errorf("Target = %q; must not be re-encoded or normalized", req.Target)
	}
	if req.Method != "GET" || req.Proto != "HTTP/1.1" {
		t.Errorf("Method/Proto = %q/%q", req.Method, req.Proto)
	}
}

func TestReducesAbsoluteFormTargetToOriginForm(t *testing.T) {
	req := parse(t, "GET http://example.com/p?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if req.Target != "/p?q=1" {
		t.Errorf("Target = %q, want /p?q=1", req.Target)
	}
}

func TestReadsContentLengthBody(t *testing.T) {
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")
	if string(req.Body) != "hello" {
		t.Errorf("Body = %q", req.Body)
	}
}

func TestZeroContentLengthYieldsEmptyBody(t *testing.T) {
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n")
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
}

func TestDecodesChunkedBody(t *testing.T) {
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	if string(req.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", req.Body, "hello world")
	}
}

func TestNoBodyWhenNeitherFramingHeaderPresent(t *testing.T) {
	req := parse(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
}

func TestDetectsUpgradeOnlyWhenBothHeadersAgree(t *testing.T) {
	ws := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if !ws.IsUpgrade {
		t.Error("websocket upgrade not detected")
	}

	// Connection: keep-alive with a stray Upgrade header is not an upgrade.
	no := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n\r\n")
	if no.IsUpgrade {
		t.Error("false positive: Connection does not list upgrade")
	}

	// Comma-separated token list must still match.
	multi := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n")
	if !multi.IsUpgrade {
		t.Error("upgrade in a comma-separated Connection list not detected")
	}
}

func TestHeadRetainsOriginalBytesForTheRelay(t *testing.T) {
	raw := "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	req := parse(t, raw)
	if string(req.Head) != raw {
		t.Errorf("Head = %q, want the original bytes %q", req.Head, raw)
	}
}

func TestOrderedNamesAreLowercased(t *testing.T) {
	req := parse(t, "GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nx-b: 2\r\n\r\n")
	got := req.OrderedNames()
	want := []string{"host", "x-a", "x-b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("OrderedNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRejectsOversizedAndMalformed(t *testing.T) {
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader("GARBAGE\r\n\r\n"))); err == nil {
		t.Error("want error for malformed request line")
	}
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(""))); err == nil {
		t.Error("want error for empty input")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd helper && go test ./internal/httpwire/`
Expected: build failure — `undefined: ReadRequest`.

- [ ] **Step 3: Write the implementation**

`helper/internal/httpwire/request.go`:
```go
// Package httpwire reads and writes HTTP/1.1 on the wire while preserving the
// details net/http discards: header order, header casing, duplicate headers,
// and the request-target exactly as the client wrote it.
//
// It knows nothing about TLS.
package httpwire

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"strconv"
	"strings"
)

const MaxBodyBytes = 256 << 20

var ErrBodyTooLarge = errors.New("httpwire: body exceeds maximum size")

type Header struct {
	Name  string
	Value string
}

type Request struct {
	Method string
	Target string // request-target, verbatim
	Proto  string
	Headers []Header
	Body    []byte
	// IsUpgrade reports an Upgrade handshake: an Upgrade header plus "upgrade"
	// among the Connection tokens.
	IsUpgrade bool
	// Head is the original request-line-plus-headers bytes, which the relay
	// replays verbatim.
	Head []byte
}

func (r *Request) Get(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func (r *Request) OrderedNames() []string {
	names := make([]string, 0, len(r.Headers))
	for _, h := range r.Headers {
		names = append(names, strings.ToLower(h.Name))
	}
	return names
}

func ReadRequest(br *bufio.Reader) (*Request, error) {
	var head bytes.Buffer

	line, err := readLine(br, &head)
	if err != nil {
		return nil, fmt.Errorf("httpwire: read request line: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("httpwire: malformed request line %q", line)
	}
	req := &Request{Method: parts[0], Target: parts[1], Proto: parts[2]}
	if !strings.HasPrefix(req.Proto, "HTTP/") {
		return nil, fmt.Errorf("httpwire: malformed protocol %q", req.Proto)
	}
	req.Target = originForm(req.Target)

	for {
		line, err := readLine(br, &head)
		if err != nil {
			return nil, fmt.Errorf("httpwire: read header: %w", err)
		}
		if line == "" {
			break
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return nil, fmt.Errorf("httpwire: malformed header %q", line)
		}
		req.Headers = append(req.Headers, Header{
			Name:  line[:i],
			Value: strings.TrimLeft(line[i+1:], " \t"),
		})
	}
	req.Head = head.Bytes()

	req.IsUpgrade = req.Get("Upgrade") != "" && hasToken(req.Get("Connection"), "upgrade")

	if err := req.readBody(br); err != nil {
		return nil, err
	}
	return req, nil
}

func (r *Request) readBody(br *bufio.Reader) error {
	if hasToken(r.Get("Transfer-Encoding"), "chunked") {
		body, err := io.ReadAll(io.LimitReader(httputil.NewChunkedReader(br), MaxBodyBytes+1))
		if err != nil {
			return fmt.Errorf("httpwire: read chunked body: %w", err)
		}
		if len(body) > MaxBodyBytes {
			return ErrBodyTooLarge
		}
		r.Body = body
		return nil
	}

	cl := r.Get("Content-Length")
	if cl == "" {
		return nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("httpwire: bad Content-Length %q", cl)
	}
	if n > MaxBodyBytes {
		return ErrBodyTooLarge
	}
	if n == 0 {
		return nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return fmt.Errorf("httpwire: read body: %w", err)
	}
	r.Body = body
	return nil
}

// readLine reads one CRLF-terminated line, echoing the raw bytes into head.
func readLine(br *bufio.Reader, head *bytes.Buffer) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	head.WriteString(line)
	return strings.TrimRight(line, "\r\n"), nil
}

// originForm strips scheme and authority from an absolute-form request-target.
func originForm(target string) string {
	for _, scheme := range []string{"http://", "https://"} {
		if len(target) >= len(scheme) && strings.EqualFold(target[:len(scheme)], scheme) {
			rest := target[len(scheme):]
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				return rest[i:]
			}
			return "/"
		}
	}
	return target
}

// hasToken reports whether a comma-separated header value contains a token.
func hasToken(value, token string) bool {
	for _, t := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(t), token) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd helper && go test ./internal/httpwire/ -v -run Test`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add helper/internal/httpwire/request.go helper/internal/httpwire/request_test.go
git commit -m "feat(helper): order-preserving HTTP/1.1 request parser"
```

---

### Task 5: HTTP/1.1 response writing

Owns **Review Focus item 3**: bodiless responses must not get a body.

**Files:**
- Create: `helper/internal/httpwire/response.go`
- Test: `helper/internal/httpwire/response_test.go`

**Interfaces:**
- Consumes: `httpwire.Header` (Task 4).
- Produces:
  - `httpwire.WriteResponse(w io.Writer, code int, reason string, headers []Header, body []byte, bodyAllowed bool) error`
  - `httpwire.WriteError(w io.Writer, code int, reason string, detail error) error`
  - `httpwire.BodyAllowed(method string, code int) bool`

- [ ] **Step 1: Write the failing test**

`helper/internal/httpwire/response_test.go`:
```go
package httpwire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteResponseSetsExactContentLengthAndDropsTransferEncoding(t *testing.T) {
	var buf bytes.Buffer
	in := []Header{
		{"Content-Type", "text/html"},
		{"Transfer-Encoding", "chunked"},
		{"Content-Length", "999"},
		{"Set-Cookie", "a=1"},
		{"Set-Cookie", "b=2"},
	}
	if err := WriteResponse(&buf, 200, "OK", in, []byte("hello"), true); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(out, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("status line = %q", out[:min(32, len(out))])
	}
	if !strings.Contains(out, "Content-Length: 5\r\n") {
		t.Errorf("want recomputed Content-Length: 5, got:\n%s", out)
	}
	if strings.Count(out, "Content-Length") != 1 {
		t.Errorf("Content-Length must appear exactly once, got:\n%s", out)
	}
	if strings.Contains(out, "Transfer-Encoding") {
		t.Errorf("Transfer-Encoding must be dropped, got:\n%s", out)
	}
	if strings.Count(out, "Set-Cookie") != 2 {
		t.Errorf("both Set-Cookie headers must survive, got:\n%s", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\nhello") {
		t.Errorf("body must follow a blank line, got:\n%s", out)
	}
}

func TestBodilessResponsesGetNoBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		code   int
	}{
		{"HEAD", "HEAD", 200},
		{"204", "GET", 204},
		{"304", "GET", 304},
		{"1xx", "GET", 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if BodyAllowed(tc.method, tc.code) {
				t.Fatalf("BodyAllowed(%q, %d) = true, want false", tc.method, tc.code)
			}
			var buf bytes.Buffer
			err := WriteResponse(&buf, tc.code, "x", []Header{{"Content-Type", "text/html"}},
				[]byte("SHOULD NOT APPEAR"), false)
			if err != nil {
				t.Fatalf("WriteResponse: %v", err)
			}
			out := buf.String()
			if strings.Contains(out, "SHOULD NOT APPEAR") {
				t.Errorf("body written for a bodiless response:\n%s", out)
			}
			if !strings.HasSuffix(out, "\r\n\r\n") {
				t.Errorf("headers must still be terminated by a blank line:\n%q", out)
			}
		})
	}
}

func TestHeadKeepsUpstreamContentLength(t *testing.T) {
	// A HEAD response advertises the length the body would have had; the helper
	// must not rewrite it to 0, which would misreport the resource size.
	var buf bytes.Buffer
	if err := WriteResponse(&buf, 200, "OK",
		[]Header{{"Content-Length", "4096"}}, nil, false); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	if !strings.Contains(buf.String(), "Content-Length: 4096\r\n") {
		t.Errorf("want upstream Content-Length preserved, got:\n%s", buf.String())
	}
}

func TestBodyAllowedForOrdinaryResponses(t *testing.T) {
	if !BodyAllowed("GET", 200) || !BodyAllowed("POST", 404) || !BodyAllowed("GET", 500) {
		t.Error("ordinary responses must allow a body")
	}
}

func TestWriteErrorCarriesDiagnosticHeaderAndBody(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, 502, "Bad Gateway", errors.New("dial tcp: refused")); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "HTTP/1.1 502 Bad Gateway\r\n") {
		t.Errorf("status line = %q", out)
	}
	if !strings.Contains(out, "X-Awesome-Tls-Error: dial tcp: refused\r\n") {
		t.Errorf("want diagnostic header, got:\n%s", out)
	}
	if !strings.Contains(out, "dial tcp: refused") {
		t.Errorf("want reason in the body, got:\n%s", out)
	}
}

func TestWriteErrorSanitizesHeaderValue(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, 502, "Bad Gateway", errors.New("line1\r\nInjected: yes")); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	if strings.Contains(buf.String(), "\r\nInjected: yes") {
		t.Errorf("CRLF in an error string must not forge a header:\n%q", buf.String())
	}
}

func min(a, b int) int { if a < b { return a }; return b }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd helper && go test ./internal/httpwire/ -run 'Write|BodyAllowed'`
Expected: build failure — `undefined: WriteResponse`.

- [ ] **Step 3: Write the implementation**

`helper/internal/httpwire/response.go`:
```go
package httpwire

import (
	"fmt"
	"io"
	"strings"
)

// BodyAllowed reports whether a response to method with this status code may
// carry a body. Writing one where it is forbidden desynchronizes the client.
func BodyAllowed(method string, code int) bool {
	if strings.EqualFold(method, "HEAD") {
		return false
	}
	switch {
	case code >= 100 && code < 200:
		return false
	case code == 204 || code == 304:
		return false
	}
	return true
}

// WriteResponse serializes a complete, buffered HTTP/1.1 response.
//
// When bodyAllowed is true, Content-Length is replaced with the exact length of
// body. When it is false, body is not written and any upstream Content-Length
// is preserved, because it describes the resource rather than this message.
// Transfer-Encoding is always dropped: the message is framed by Content-Length.
func WriteResponse(w io.Writer, code int, reason string, headers []Header, body []byte, bodyAllowed bool) error {
	var b strings.Builder

	if reason == "" {
		reason = "Status"
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, sanitizeHeaderValue(reason))

	for _, h := range headers {
		switch {
		case strings.EqualFold(h.Name, "Transfer-Encoding"):
			continue
		case strings.EqualFold(h.Name, "Content-Length") && bodyAllowed:
			continue // replaced below
		}
		fmt.Fprintf(&b, "%s: %s\r\n", sanitizeHeaderName(h.Name), sanitizeHeaderValue(h.Value))
	}

	if bodyAllowed {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if bodyAllowed && len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// WriteError reports a helper-side failure in a form visible in Caido's history.
func WriteError(w io.Writer, code int, reason string, detail error) error {
	msg := "unknown error"
	if detail != nil {
		msg = detail.Error()
	}
	body := []byte("Awesome TLS: " + msg + "\n")
	return WriteResponse(w, code, reason, []Header{
		{"Content-Type", "text/plain; charset=utf-8"},
		{"X-Awesome-Tls-Error", msg},
		{"Connection", "close"},
	}, body, true)
}

// sanitizeHeaderValue removes CR and LF so an upstream or error string cannot
// forge additional headers.
func sanitizeHeaderValue(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

func sanitizeHeaderName(n string) string {
	return strings.NewReplacer("\r", "", "\n", "", ":", "", " ", "").Replace(n)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd helper && go test ./internal/httpwire/ -v`
Expected: every test in the package PASSes.

- [ ] **Step 5: Commit**

```bash
git add helper/internal/httpwire/response.go helper/internal/httpwire/response_test.go
git commit -m "feat(helper): buffered HTTP/1.1 response writer with bodiless-status handling"
```

---

### Task 6: ClientHello to uTLS spec, and the profile registry

**Files:**
- Create: `helper/internal/fingerprint/spec.go`, `helper/internal/fingerprint/profiles.go`
- Test: `helper/internal/fingerprint/spec_test.go`, `helper/internal/fingerprint/profiles_test.go`
- Create: `helper/internal/fingerprint/testdata/chrome.hello` (hex, one line)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `fingerprint.SpecFromRaw(raw []byte) (*utls.ClientHelloSpec, error)`
  - `fingerprint.SpecFromHex(s string) (*utls.ClientHelloSpec, error)`
  - `fingerprint.Profiles() []string` — sorted profile names
  - `fingerprint.DefaultProfile() string`
  - `fingerprint.Lookup(name string) (profiles.ClientProfile, bool)`
  - `fingerprint.WithClientHello(base profiles.ClientProfile, spec *utls.ClientHelloSpec) profiles.ClientProfile`

- [ ] **Step 1: Add the dependencies**

```bash
cd helper
go get github.com/bogdanfinn/tls-client@v1.16.0
go get github.com/bogdanfinn/utls@v1.7.8-barnius
go get github.com/bogdanfinn/fhttp@v0.6.9
go mod tidy
```

- [ ] **Step 2: Record a real ClientHello as test data**

```bash
cd helper/internal/fingerprint && mkdir -p testdata
cat > /tmp/dump_hello.go <<'GO'
//go:build ignore
package main

import (
	"encoding/hex"
	"fmt"
	utls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/tls-client/profiles"
)

func main() {
	p := profiles.Chrome_150
	spec, err := p.GetClientHelloSpec()
	if err != nil { panic(err) }
	// This fork's UClient takes six arguments:
	// (conn, config, id, randomExtOrder, forceHttp1, disableHttp3)
	uconn := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, utls.HelloCustom, false, false, false)
	if err := uconn.ApplyPreset(&spec); err != nil { panic(err) }
	if err := uconn.BuildHandshakeState(); err != nil { panic(err) }
	fmt.Println(hex.EncodeToString(uconn.HandshakeState.Hello.Raw))
}
GO
go run /tmp/dump_hello.go > testdata/chrome.hello
wc -c testdata/chrome.hello   # expect several hundred bytes of hex
```

This produces a genuine Chrome-150 ClientHello to exercise the parser against. If `ApplyPreset`
requires a non-nil conn in this version, dial a throwaway TCP listener first rather than passing `nil`.

- [ ] **Step 3: Write the failing tests**

`helper/internal/fingerprint/spec_test.go`:
```go
package fingerprint

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	utls "github.com/bogdanfinn/utls"
)

func loadHello(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/chrome.hello")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("decode testdata: %v", err)
	}
	return raw
}

func TestSpecFromRawParsesARealClientHello(t *testing.T) {
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Error("no cipher suites parsed")
	}
	if len(spec.Extensions) == 0 {
		t.Error("no extensions parsed")
	}
}

func TestSpecFromRawReplacesECHWithGREASEPlaceholder(t *testing.T) {
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	for i, ext := range spec.Extensions {
		if g, ok := ext.(*utls.GenericExtension); ok && g.Id == utls.ExtensionECH {
			t.Errorf("extension %d is still a generic ECH extension; real ECH is unsupported "+
				"and must be replaced with a GREASE placeholder", i)
		}
	}
}

func TestSpecFromRawUsesRealPSKResumption(t *testing.T) {
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.FakePreSharedKeyExtension); ok {
			t.Errorf("extension %d is a fake PSK extension; a fake PSK cannot complete a "+
				"handshake, so resumption must be requested as real", i)
		}
	}
}

func TestSpecFromHexRejectsBadInput(t *testing.T) {
	if _, err := SpecFromHex(""); err == nil {
		t.Error("want error for empty hex")
	}
	if _, err := SpecFromHex("zzzz"); err == nil {
		t.Error("want error for non-hex")
	}
	if _, err := SpecFromHex("160301"); err == nil {
		t.Error("want error for a truncated record")
	}
}
```

`helper/internal/fingerprint/profiles_test.go`:
```go
package fingerprint

import (
	"sort"
	"testing"
)

func TestProfilesAreSortedNonEmptyAndContainKnownNames(t *testing.T) {
	got := Profiles()
	if len(got) < 20 {
		t.Fatalf("expected the bundled library's full profile list, got %d", len(got))
	}
	if !sort.StringsAreSorted(got) {
		t.Error("Profiles() must be sorted so the UI dropdown is stable")
	}
	want := map[string]bool{"chrome_150": false, "firefox_148": false, "safari_ios_26_0": false}
	for _, p := range got {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("profile %q missing from Profiles()", name)
		}
	}
}

func TestDefaultProfileIsResolvable(t *testing.T) {
	d := DefaultProfile()
	if _, ok := Lookup(d); !ok {
		t.Fatalf("DefaultProfile() = %q, which Lookup rejects", d)
	}
}

func TestLookupRejectsUnknownNames(t *testing.T) {
	if _, ok := Lookup("netscape_4"); ok {
		t.Error("Lookup accepted an unknown profile")
	}
	if _, ok := Lookup(""); ok {
		t.Error("Lookup accepted an empty profile")
	}
}

func TestWithClientHelloKeepsTheHTTP2LayerOfTheBase(t *testing.T) {
	base, ok := Lookup("chrome_150")
	if !ok {
		t.Fatal("chrome_150 missing")
	}
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	custom := WithClientHello(base, spec)

	if len(custom.GetSettings()) != len(base.GetSettings()) {
		t.Error("HTTP/2 SETTINGS must come from the base profile")
	}
	if got, want := custom.GetConnectionFlow(), base.GetConnectionFlow(); got != want {
		t.Errorf("connection flow = %d, want %d", got, want)
	}
	ph, bph := custom.GetPseudoHeaderOrder(), base.GetPseudoHeaderOrder()
	if len(ph) != len(bph) {
		t.Fatalf("pseudo-header order length = %d, want %d", len(ph), len(bph))
	}
	for i := range bph {
		if ph[i] != bph[i] {
			t.Errorf("pseudo-header %d = %q, want %q", i, ph[i], bph[i])
		}
	}
	if custom.GetClientHelloId().Client == base.GetClientHelloId().Client {
		t.Error("the custom profile must carry its own ClientHelloID, not the base one")
	}
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd helper && go test ./internal/fingerprint/`
Expected: build failure — `undefined: SpecFromRaw`, `undefined: Profiles`.

- [ ] **Step 5: Write the implementation**

`helper/internal/fingerprint/spec.go`:
```go
// Package fingerprint converts captured ClientHello bytes into uTLS specs and
// resolves the bundled browser profiles. It knows nothing about HTTP framing.
package fingerprint

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	utls "github.com/bogdanfinn/utls"
)

// SpecFromHex parses a hex-encoded ClientHello.
func SpecFromHex(s string) (*utls.ClientHelloSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("fingerprint: empty client hello")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: client hello is not hex: %w", err)
	}
	return SpecFromRaw(raw)
}

// SpecFromRaw converts raw ClientHello bytes (a complete TLS handshake record)
// into a spec uTLS can replay.
func SpecFromRaw(raw []byte) (*utls.ClientHelloSpec, error) {
	if len(raw) < 5 {
		return nil, errors.New("fingerprint: client hello too short to be a TLS record")
	}

	f := &utls.Fingerprinter{
		// Pass unrecognized extensions through, so an unfamiliar browser still
		// reproduces byte-for-byte.
		AllowBluntMimicry: true,
		// Request a usable PSK extension. Without this uTLS yields a "fake" PSK
		// that cannot complete resumption, which the Burp extension works around
		// by swapping the extension out afterwards.
		RealPSKResumption: true,
	}
	spec, err := f.RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: parse client hello: %w", err)
	}

	for i, ext := range spec.Extensions {
		// Real Encrypted ClientHello is not supported; send a GREASE placeholder,
		// which is what a browser with ECH disabled looks like on the wire.
		if g, ok := ext.(*utls.GenericExtension); ok && g.Id == utls.ExtensionECH {
			spec.Extensions[i] = utls.BoringGREASEECH()
		}
	}
	return spec, nil
}
```

`helper/internal/fingerprint/profiles.go`:
```go
package fingerprint

import (
	"maps"
	"slices"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Profiles lists every bundled profile name, sorted.
func Profiles() []string {
	return slices.Sorted(maps.Keys(profiles.MappedTLSClients))
}

// DefaultProfile is the library's current default, which tracks recent Chrome.
func DefaultProfile() string {
	return profiles.DefaultClientProfile.GetClientHelloId().Client
}

func Lookup(name string) (profiles.ClientProfile, bool) {
	p, ok := profiles.MappedTLSClients[name]
	return p, ok
}

// WithClientHello returns base with its TLS ClientHello replaced by spec,
// keeping base's HTTP/2 layer: SETTINGS, their order, connection flow,
// priorities and pseudo-header order.
func WithClientHello(base profiles.ClientProfile, spec *utls.ClientHelloSpec) profiles.ClientProfile {
	id := utls.ClientHelloID{
		Client:      "AwesomeTLSCaptured",
		Version:     "1",
		SpecFactory: func() (utls.ClientHelloSpec, error) { return *spec, nil },
	}
	return profiles.NewClientProfile(
		id,
		base.GetSettings(),
		base.GetSettingsOrder(),
		base.GetPseudoHeaderOrder(),
		base.GetConnectionFlow(),
		base.GetPriorities(),
		base.GetHeaderPriority(),
		base.GetStreamID(),
		base.GetAllowHTTP(),
		base.GetHttp3Settings(),
		base.GetHttp3SettingsOrder(),
		base.GetHttp3PriorityParam(),
		base.GetHttp3PseudoHeaderOrder(),
		base.GetHttp3SendGreaseFrames(),
	)
}
```

If `DefaultProfile()` does not return a key present in `MappedTLSClients`, make it return the literal
`"chrome_150"` instead and let `TestDefaultProfileIsResolvable` guard it.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd helper && go test ./internal/fingerprint/ -v`
Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add helper/internal/fingerprint/spec.go helper/internal/fingerprint/profiles.go \
        helper/internal/fingerprint/spec_test.go helper/internal/fingerprint/profiles_test.go \
        helper/internal/fingerprint/testdata/ helper/go.mod helper/go.sum
git commit -m "feat(helper): ClientHello parsing with ECH/PSK handling and profile registry"
```

---

### Task 7: JA3 and JA4 fingerprint strings

The UI shows these so the operator can compare a captured hello against what a server reports without a
round trip. Implemented over a self-owned ClientHello field parser rather than uTLS internals, so the
field extraction is directly testable.

**Files:**
- Create: `helper/internal/fingerprint/ja.go`
- Test: `helper/internal/fingerprint/ja_test.go`

**Interfaces:**
- Consumes: `fingerprint.SpecFromRaw` only for the existing testdata helper.
- Produces:
  - `fingerprint.Info{JA3, JA3Text, JA4 string}`
  - `fingerprint.Analyze(raw []byte) (Info, error)`
  - unexported, covered directly by in-package tests: `parseClientHello([]byte) (*parsed, error)`,
    `ja3Text(*parsed) string`, `ja4(*parsed) string`, `ja4a/ja4b/ja4c(*parsed) string`, `isGREASE(uint16) bool`

- [ ] **Step 1: Write the failing test**

`helper/internal/fingerprint/ja_test.go`:
```go
package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// --- synthetic ClientHello builder -----------------------------------------
//
// Hand-built so every expectation below is checkable by eye.

type helloOpts struct {
	legacyVersion uint16
	ciphers       []uint16
	sni           string   // "" omits the extension
	alpn          []string // nil omits the extension
	curves        []uint16
	pointFormats  []uint8
	sigAlgs       []uint16
	supportedVers []uint16 // nil omits the extension
	extraExts     []uint16 // emitted as empty extensions, in order
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func ext(id uint16, payload []byte) []byte {
	out := append(u16(id), u16(uint16(len(payload)))...)
	return append(out, payload...)
}

func buildHello(o helloOpts) []byte {
	var exts []byte

	if o.sni != "" {
		name := append([]byte{0x00}, u16(uint16(len(o.sni)))...)
		name = append(name, []byte(o.sni)...)
		list := append(u16(uint16(len(name))), name...)
		exts = append(exts, ext(0x0000, list)...)
	}
	if o.curves != nil {
		var b []byte
		for _, c := range o.curves {
			b = append(b, u16(c)...)
		}
		exts = append(exts, ext(0x000a, append(u16(uint16(len(b))), b...))...)
	}
	if o.pointFormats != nil {
		b := append([]byte{byte(len(o.pointFormats))}, o.pointFormats...)
		exts = append(exts, ext(0x000b, b)...)
	}
	if o.sigAlgs != nil {
		var b []byte
		for _, s := range o.sigAlgs {
			b = append(b, u16(s)...)
		}
		exts = append(exts, ext(0x000d, append(u16(uint16(len(b))), b...))...)
	}
	if o.alpn != nil {
		var list []byte
		for _, p := range o.alpn {
			list = append(list, byte(len(p)))
			list = append(list, []byte(p)...)
		}
		exts = append(exts, ext(0x0010, append(u16(uint16(len(list))), list...))...)
	}
	if o.supportedVers != nil {
		var b []byte
		for _, v := range o.supportedVers {
			b = append(b, u16(v)...)
		}
		exts = append(exts, ext(0x002b, append([]byte{byte(len(b))}, b...))...)
	}
	for _, id := range o.extraExts {
		exts = append(exts, ext(id, nil)...)
	}

	var body []byte
	body = append(body, u16(o.legacyVersion)...)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // empty session id
	var ciphers []byte
	for _, c := range o.ciphers {
		ciphers = append(ciphers, u16(c)...)
	}
	body = append(body, u16(uint16(len(ciphers)))...)
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00) // one compression method: null
	body = append(body, u16(uint16(len(exts)))...)
	body = append(body, exts...)

	// handshake header: type 0x01, 24-bit length
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// record header: handshake(0x16), version, 16-bit length
	rec := append([]byte{0x16}, u16(0x0301)...)
	rec = append(rec, u16(uint16(len(hs)))...)
	return append(rec, hs...)
}

func sampleOpts() helloOpts {
	return helloOpts{
		legacyVersion: 0x0303,
		// 0x0a0a is GREASE and must be excluded everywhere.
		ciphers:       []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b},
		sni:           "example.com",
		alpn:          []string{"h2", "http/1.1"},
		curves:        []uint16{0x1a1a, 0x001d, 0x0017},
		pointFormats:  []uint8{0x00},
		sigAlgs:       []uint16{0x0403, 0x0804, 0x0401},
		supportedVers: []uint16{0x2a2a, 0x0304, 0x0303},
		extraExts:     []uint16{0x0017, 0x002d, 0x7a7a},
	}
}

// --- field parsing ---------------------------------------------------------

func TestParseClientHelloExtractsFieldsAndDropsGREASE(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	if p.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#04x", p.LegacyVersion)
	}
	if got, want := fmt.Sprint(p.Ciphers), fmt.Sprint([]uint16{0x1301, 0x1302, 0xc02b}); got != want {
		t.Errorf("Ciphers = %s, want %s (GREASE removed, order kept)", got, want)
	}
	// Extensions in wire order, GREASE (0x7a7a) removed.
	wantExts := []uint16{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b, 0x0017, 0x002d}
	if got, want := fmt.Sprint(p.Extensions), fmt.Sprint(wantExts); got != want {
		t.Errorf("Extensions = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(p.Curves), fmt.Sprint([]uint16{0x001d, 0x0017}); got != want {
		t.Errorf("Curves = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(p.PointFormats), fmt.Sprint([]uint8{0x00}); got != want {
		t.Errorf("PointFormats = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(p.SigAlgs), fmt.Sprint([]uint16{0x0403, 0x0804, 0x0401}); got != want {
		t.Errorf("SigAlgs = %s, want %s (original order)", got, want)
	}
	if got, want := fmt.Sprint(p.SupportedVersions), fmt.Sprint([]uint16{0x0304, 0x0303}); got != want {
		t.Errorf("SupportedVersions = %s, want %s", got, want)
	}
	if !p.HasSNI {
		t.Error("HasSNI = false")
	}
	if got, want := fmt.Sprint(p.ALPN), fmt.Sprint([]string{"h2", "http/1.1"}); got != want {
		t.Errorf("ALPN = %s, want %s", got, want)
	}
}

func TestParseClientHelloHandlesMissingOptionalExtensions(t *testing.T) {
	p, err := parseClientHello(buildHello(helloOpts{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0x1301},
	}))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if p.HasSNI || len(p.ALPN) != 0 || len(p.Curves) != 0 || len(p.SigAlgs) != 0 {
		t.Errorf("absent extensions must yield zero values, got %+v", p)
	}
}

func TestParseClientHelloRejectsTruncatedInput(t *testing.T) {
	full := buildHello(sampleOpts())
	for _, n := range []int{0, 4, 9, 20, len(full) - 1} {
		if _, err := parseClientHello(full[:n]); err == nil {
			t.Errorf("want error for input truncated to %d bytes", n)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x7a7a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0a0b, 0x001d, 0x0000} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true", v)
		}
	}
}

// --- JA3 -------------------------------------------------------------------

func TestJA3TextAndHash(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	// version,ciphers,extensions,curves,pointformats — all decimal, GREASE removed.
	const want = "771,4865-4866-49195,0-10-11-13-16-43-23-45,29-23,0"
	if got := ja3Text(p); got != want {
		t.Errorf("ja3Text:\n got %q\nwant %q", got, want)
	}

	info, err := Analyze(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	wantHash := fmt.Sprintf("%x", md5.Sum([]byte(want)))
	if info.JA3 != wantHash {
		t.Errorf("JA3 = %q, want md5 of the JA3 string %q", info.JA3, wantHash)
	}
	if info.JA3Text != want {
		t.Errorf("JA3Text = %q", info.JA3Text)
	}
}

// --- JA4 -------------------------------------------------------------------

func TestJA4APart(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	// t  = TCP
	// 13 = TLS 1.3 (highest in supported_versions, GREASE ignored)
	// d  = SNI present
	// 03 = 3 ciphers after GREASE removal
	// 08 = 8 extensions after GREASE removal, SNI and ALPN included in the count
	// h2 = first and last character of the first ALPN value
	const want = "t13d0308h2"
	if got := ja4a(p); got != want {
		t.Errorf("ja4a = %q, want %q", got, want)
	}
}

func TestJA4APartWithoutSNIorALPNandWithLegacyVersion(t *testing.T) {
	o := helloOpts{legacyVersion: 0x0303, ciphers: []uint16{0x1301, 0x1302}}
	p, err := parseClientHello(buildHello(o))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	// i = no SNI; 00 = no ALPN; version falls back to the legacy field (TLS 1.2)
	const want = "t12i0200" + "00"
	if got := ja4a(p); got != want {
		t.Errorf("ja4a = %q, want %q", got, want)
	}
}

func TestJA4ALPNUsesFirstAndLastCharacter(t *testing.T) {
	for _, tc := range []struct{ alpn, want string }{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"x", "xx"},
	} {
		o := sampleOpts()
		o.alpn = []string{tc.alpn}
		p, err := parseClientHello(buildHello(o))
		if err != nil {
			t.Fatalf("parseClientHello: %v", err)
		}
		if got := ja4a(p)[8:]; got != tc.want {
			t.Errorf("ALPN %q -> %q, want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestJA4BHashesSortedCipherList(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	const sorted = "1301,1302,c02b"
	sum := sha256.Sum256([]byte(sorted))
	want := hex.EncodeToString(sum[:])[:12]
	if got := ja4b(p); got != want {
		t.Errorf("ja4b = %q, want first 12 hex of sha256(%q) = %q", got, sorted, want)
	}
}

func TestJA4CHashesSortedExtensionsPlusSignatureAlgorithms(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	// Extensions sorted ascending, with SNI (0000) and ALPN (0010) removed,
	// then an underscore, then the signature algorithms in original order.
	const input = "000a,000b,000d,0017,002b,002d_0403,0804,0401"
	sum := sha256.Sum256([]byte(input))
	want := hex.EncodeToString(sum[:])[:12]
	if got := ja4c(p); got != want {
		t.Errorf("ja4c = %q, want first 12 hex of sha256(%q) = %q", got, input, want)
	}
}

func TestJA4EmptyListsHashToZeros(t *testing.T) {
	p, err := parseClientHello(buildHello(helloOpts{legacyVersion: 0x0303}))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if got := ja4b(p); got != "000000000000" {
		t.Errorf("ja4b with no ciphers = %q, want zeros", got)
	}
	if got := ja4c(p); got != "000000000000" {
		t.Errorf("ja4c with no extensions = %q, want zeros", got)
	}
}

func TestJA4AssemblesThreeUnderscoreSeparatedParts(t *testing.T) {
	raw := buildHello(sampleOpts())
	p, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	want := ja4a(p) + "_" + ja4b(p) + "_" + ja4c(p)

	info, err := Analyze(raw)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if info.JA4 != want {
		t.Errorf("JA4 = %q, want %q", info.JA4, want)
	}
	if n := strings.Count(info.JA4, "_"); n != 2 {
		t.Errorf("JA4 must have exactly two separators, got %d: %q", n, info.JA4)
	}
}

// --- real hello ------------------------------------------------------------

func TestAnalyzeAcceptsTheRecordedChromeHello(t *testing.T) {
	info, err := Analyze(loadHello(t))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(info.JA3) != 32 {
		t.Errorf("JA3 = %q, want a 32-character md5 hex digest", info.JA3)
	}
	if !strings.HasPrefix(info.JA4, "t13d") {
		t.Errorf("JA4 = %q, want a TLS 1.3 TCP hello with SNI", info.JA4)
	}
	// Freeze the values once confirmed against an external reporter in Task 19.
	t.Logf("recorded chrome hello: ja3=%s ja4=%s", info.JA3, info.JA4)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd helper && go test ./internal/fingerprint/ -run JA`
Expected: build failure — `undefined: parseClientHello`.

- [ ] **Step 3: Write the implementation**

`helper/internal/fingerprint/ja.go`:
```go
package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Info holds the fingerprints of a ClientHello, for display.
type Info struct {
	JA3     string `json:"ja3"`
	JA3Text string `json:"ja3Text"`
	JA4     string `json:"ja4"`
}

// Analyze computes JA3 and JA4 for a raw ClientHello record.
func Analyze(raw []byte) (Info, error) {
	p, err := parseClientHello(raw)
	if err != nil {
		return Info{}, err
	}
	text := ja3Text(p)
	return Info{
		JA3:     fmt.Sprintf("%x", md5.Sum([]byte(text))),
		JA3Text: text,
		JA4:     ja4(p),
	}, nil
}

// TLS extension numbers this code reads by name.
const (
	extServerName        uint16 = 0x0000
	extSupportedGroups   uint16 = 0x000a
	extECPointFormats    uint16 = 0x000b
	extSignatureAlgs     uint16 = 0x000d
	extALPN              uint16 = 0x0010
	extSupportedVersions uint16 = 0x002b
)

type parsed struct {
	LegacyVersion     uint16
	Ciphers           []uint16 // GREASE removed, wire order
	Extensions        []uint16 // GREASE removed, wire order
	Curves            []uint16 // GREASE removed
	PointFormats      []uint8
	SigAlgs           []uint16 // wire order, GREASE removed
	SupportedVersions []uint16 // GREASE removed
	ALPN              []string
	HasSNI            bool
}

var errTruncated = errors.New("fingerprint: truncated client hello")

// cursor is a bounds-checked big-endian reader.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || len(c.b) < n {
		c.err = errTruncated
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	b := c.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (c *cursor) u16() uint16 {
	b := c.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (c *cursor) u24() int {
	b := c.take(3)
	if b == nil {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// isGREASE reports whether a value is a GREASE placeholder (RFC 8701): both
// bytes equal and of the form 0xNaNa.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}

func keepNonGREASE(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// parseClientHello reads the fields JA3 and JA4 are computed from out of a
// complete TLS handshake record.
func parseClientHello(raw []byte) (*parsed, error) {
	c := &cursor{b: raw}

	if t := c.u8(); t != 0x16 {
		if c.err != nil {
			return nil, c.err
		}
		return nil, fmt.Errorf("fingerprint: record type %#02x is not handshake", t)
	}
	c.u16()                 // record version
	recLen := int(c.u16())  // record length
	if c.err != nil {
		return nil, c.err
	}
	if len(c.b) < recLen {
		return nil, errTruncated
	}
	c.b = c.b[:recLen] // a ClientHello must fit in one record here

	if t := c.u8(); t != 0x01 {
		if c.err != nil {
			return nil, c.err
		}
		return nil, fmt.Errorf("fingerprint: handshake type %#02x is not client_hello", t)
	}
	bodyLen := c.u24()
	if c.err != nil {
		return nil, c.err
	}
	if len(c.b) < bodyLen {
		return nil, errTruncated
	}
	c.b = c.b[:bodyLen]

	p := &parsed{}
	p.LegacyVersion = c.u16()
	c.take(32)                 // random
	c.take(c.u8())             // legacy_session_id

	cipherBytes := c.take(int(c.u16()))
	if c.err != nil {
		return nil, c.err
	}
	if len(cipherBytes)%2 != 0 {
		return nil, errTruncated
	}
	var ciphers []uint16
	for i := 0; i < len(cipherBytes); i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(cipherBytes[i:i+2]))
	}
	p.Ciphers = keepNonGREASE(ciphers)

	c.take(c.u8()) // legacy_compression_methods

	// Extensions are optional in the wire format.
	if len(c.b) == 0 && c.err == nil {
		return p, nil
	}
	extBytes := c.take(int(c.u16()))
	if c.err != nil {
		return nil, c.err
	}

	e := &cursor{b: extBytes}
	for len(e.b) > 0 {
		id := e.u16()
		payload := e.take(int(e.u16()))
		if e.err != nil {
			return nil, e.err
		}
		if !isGREASE(id) {
			p.Extensions = append(p.Extensions, id)
		}
		if err := p.readExtension(id, payload); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *parsed) readExtension(id uint16, payload []byte) error {
	d := &cursor{b: payload}
	switch id {
	case extServerName:
		p.HasSNI = true
	case extSupportedGroups:
		b := d.take(int(d.u16()))
		if d.err != nil {
			return d.err
		}
		var groups []uint16
		for i := 0; i+1 < len(b); i += 2 {
			groups = append(groups, binary.BigEndian.Uint16(b[i:i+2]))
		}
		p.Curves = keepNonGREASE(groups)
	case extECPointFormats:
		b := d.take(d.u8())
		if d.err != nil {
			return d.err
		}
		p.PointFormats = append(p.PointFormats, b...)
	case extSignatureAlgs:
		b := d.take(int(d.u16()))
		if d.err != nil {
			return d.err
		}
		var algs []uint16
		for i := 0; i+1 < len(b); i += 2 {
			algs = append(algs, binary.BigEndian.Uint16(b[i:i+2]))
		}
		p.SigAlgs = keepNonGREASE(algs)
	case extALPN:
		b := d.take(int(d.u16()))
		if d.err != nil {
			return d.err
		}
		l := &cursor{b: b}
		for len(l.b) > 0 {
			v := l.take(l.u8())
			if l.err != nil {
				return l.err
			}
			p.ALPN = append(p.ALPN, string(v))
		}
	case extSupportedVersions:
		b := d.take(d.u8())
		if d.err != nil {
			return d.err
		}
		var vers []uint16
		for i := 0; i+1 < len(b); i += 2 {
			vers = append(vers, binary.BigEndian.Uint16(b[i:i+2]))
		}
		p.SupportedVersions = keepNonGREASE(vers)
	}
	return nil
}

// ja3Text builds the JA3 string:
// version,ciphers,extensions,curves,point-formats — decimal, dash-separated.
func ja3Text(p *parsed) string {
	join := func(vs []uint16) string {
		parts := make([]string, len(vs))
		for i, v := range vs {
			parts[i] = strconv.Itoa(int(v))
		}
		return strings.Join(parts, "-")
	}
	formats := make([]string, len(p.PointFormats))
	for i, f := range p.PointFormats {
		formats[i] = strconv.Itoa(int(f))
	}
	return strings.Join([]string{
		strconv.Itoa(int(p.LegacyVersion)),
		join(p.Ciphers),
		join(p.Extensions),
		join(p.Curves),
		strings.Join(formats, "-"),
	}, ",")
}

func ja4(p *parsed) string {
	return ja4a(p) + "_" + ja4b(p) + "_" + ja4c(p)
}

// ja4a is the readable prefix: protocol, version, SNI flag, cipher count,
// extension count, ALPN marker.
func ja4a(p *parsed) string {
	version := p.LegacyVersion
	for _, v := range p.SupportedVersions {
		if v > version {
			version = v
		}
	}
	var ver string
	switch version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	case 0x0300:
		ver = "s3"
	default:
		ver = "00"
	}

	sni := "i"
	if p.HasSNI {
		sni = "d"
	}

	alpn := "00"
	if len(p.ALPN) > 0 && len(p.ALPN[0]) > 0 {
		v := p.ALPN[0]
		alpn = string([]byte{v[0], v[len(v)-1]})
	}

	// "t" for TCP: this helper never speaks QUIC.
	return fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, cap99(len(p.Ciphers)), cap99(len(p.Extensions)), alpn)
}

func cap99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// ja4b hashes the sorted cipher list.
func ja4b(p *parsed) string {
	if len(p.Ciphers) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(strings.Join(sortedHex(p.Ciphers), ","))
}

// ja4c hashes the sorted extension list (excluding SNI and ALPN, which are
// already represented in the prefix) joined to the signature algorithms in
// their original order.
func ja4c(p *parsed) string {
	exts := make([]uint16, 0, len(p.Extensions))
	for _, e := range p.Extensions {
		if e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(strings.Join(sortedHex(exts), ",") + "_" + strings.Join(hexList(p.SigAlgs), ","))
}

func sortedHex(vs []uint16) []string {
	out := hexList(vs)
	slices.Sort(out)
	return out
}

func hexList(vs []uint16) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = fmt.Sprintf("%04x", v)
	}
	return out
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd helper && go test ./internal/fingerprint/ -v`
Expected: every test PASSes. Note the `t.Logf` output from
`TestAnalyzeAcceptsTheRecordedChromeHello` — Task 19 confirms those two values against an external
reporter and then freezes them into an assertion.

- [ ] **Step 5: Commit**

```bash
git add helper/internal/fingerprint/ja.go helper/internal/fingerprint/ja_test.go
git commit -m "feat(helper): JA3 and JA4 computation over a self-owned ClientHello parser"
```

---

### Task 8: Client cache and forwarding one request

Owns **Review Focus item 1**: the `Host` header must never decide where the helper dials.

**Files:**
- Create: `helper/internal/forward/cache.go`, `helper/internal/forward/forward.go`
- Test: `helper/internal/forward/cache_test.go`, `helper/internal/forward/forward_test.go`

**Interfaces:**
- Consumes: `preamble.Config` (Task 3), `httpwire.Request`/`Header`/`WriteResponse`/`BodyAllowed` (Tasks 4-5), `fingerprint.Lookup`/`SpecFromHex`/`WithClientHello` (Task 6).
- Produces:
  - `forward.NewCache(ttl time.Duration) *Cache`, `(*Cache).Get(*preamble.Config) (tls_client.HttpClient, error)`, `(*Cache).Len() int`, `(*Cache).Evict(now time.Time)`, `(*Cache).Close()`
  - `forward.Send(client tls_client.HttpClient, cfg *preamble.Config, req *httpwire.Request) (*Result, error)`
  - `forward.Result{Code int, Reason string, Headers []httpwire.Header, Body []byte}`

- [ ] **Step 1: Write the failing cache test**

`helper/internal/forward/cache_test.go`:
```go
package forward

import (
	"testing"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

func cfg(profile, hello string, timeout int) *preamble.Config {
	return &preamble.Config{
		Target:      preamble.Target{Host: "example.com", Port: 443, TLS: true},
		Profile:     profile,
		ClientHello: hello,
		TimeoutSec:  timeout,
	}
}

func TestCacheReusesOneClientPerConfiguration(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()

	a, err := c.Get(cfg("chrome_150", "", 30))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	b, err := c.Get(cfg("chrome_150", "", 30))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a != b {
		t.Error("identical configurations must share one client, so connections pool like a browser's")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestCacheSeparatesClientsByProfileAndTimeout(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()

	base, _ := c.Get(cfg("chrome_150", "", 30))
	for name, other := range map[string]*preamble.Config{
		"different profile": cfg("firefox_148", "", 30),
		"different timeout": cfg("chrome_150", "", 60),
	} {
		got, err := c.Get(other)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == base {
			t.Errorf("%s must not share a client", name)
		}
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
}

func TestCacheRejectsUnknownProfile(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()
	if _, err := c.Get(cfg("netscape_4", "", 30)); err == nil {
		t.Error("want error for an unknown profile")
	}
}

func TestCacheEvictsIdleEntries(t *testing.T) {
	c := NewCache(10 * time.Minute)
	defer c.Close()

	if _, err := c.Get(cfg("chrome_150", "", 30)); err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Evict(time.Now().Add(5 * time.Minute))
	if c.Len() != 1 {
		t.Errorf("entry evicted too early: Len = %d", c.Len())
	}
	c.Evict(time.Now().Add(11 * time.Minute))
	if c.Len() != 0 {
		t.Errorf("idle entry not evicted: Len = %d", c.Len())
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd helper && go test ./internal/forward/`
Expected: build failure — `undefined: NewCache`.

- [ ] **Step 3: Write the cache**

`helper/internal/forward/cache.go`:
```go
// Package forward re-sends a parsed request through a browser-profiled TLS
// client and turns the answer back into bytes on the wire.
package forward

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/json/caido-awesome-tls/helper/internal/fingerprint"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

type entry struct {
	client   tls_client.HttpClient
	lastUsed time.Time
}

// Cache holds one client per distinct configuration so that TLS sessions and
// connections pool the way a browser's do. Building a fresh client per request
// would force a new handshake every time, which is itself an anomalous pattern.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*entry
	ttl     time.Duration
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{entries: make(map[string]*entry), ttl: ttl}
}

func key(c *preamble.Config) string {
	h := sha256.Sum256([]byte(c.ClientHello))
	return fmt.Sprintf("%s|%s|%d", c.Profile, hex.EncodeToString(h[:8]), c.TimeoutSec)
}

func (c *Cache) Get(cfg *preamble.Config) (tls_client.HttpClient, error) {
	k := key(cfg)

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[k]; ok {
		e.lastUsed = time.Now()
		return e.client, nil
	}

	client, err := build(cfg)
	if err != nil {
		return nil, err
	}
	c.entries[k] = &entry{client: client, lastUsed: time.Now()}
	return client, nil
}

func build(cfg *preamble.Config) (tls_client.HttpClient, error) {
	profile, ok := fingerprint.Lookup(cfg.Profile)
	if !ok {
		return nil, fmt.Errorf("forward: unknown profile %q", cfg.Profile)
	}

	// A captured ClientHello replaces the TLS layer; the HTTP/2 layer still
	// comes from the named profile.
	if cfg.ClientHello != "" {
		spec, err := fingerprint.SpecFromHex(cfg.ClientHello)
		if err != nil {
			return nil, err
		}
		profile = fingerprint.WithClientHello(profile, spec)
	}

	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(cfg.TimeoutSec),
		// Load-bearing: fhttp otherwise decompresses the body while leaving
		// Content-Encoding in place, handing Caido a self-contradicting response.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true}),
	}

	// NewHttpClient with an explicit option list attaches no cookie jar, which
	// is what a proxy wants: the client's own cookies must pass through untouched.
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Evict drops entries idle for longer than the TTL.
func (c *Cache) Evict(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.Sub(e.lastUsed) > c.ttl {
			e.client.CloseIdleConnections()
			delete(c.entries, k)
		}
	}
}

func (c *Cache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		e.client.CloseIdleConnections()
		delete(c.entries, k)
	}
}
```

If `CloseIdleConnections` is not on the `HttpClient` interface in this version, drop those two calls and
let the entries be garbage collected.

- [ ] **Step 4: Run the cache test to verify it passes**

Run: `cd helper && go test ./internal/forward/ -run Cache -v`
Expected: all four cache tests PASS.

- [ ] **Step 5: Write the failing forwarding test**

`helper/internal/forward/forward_test.go`:
```go
package forward

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

// tlsServer starts an HTTPS test server and returns a config pointing at it.
func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, *preamble.Config) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	u := strings.TrimPrefix(srv.URL, "https://")
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", u, err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	return srv, &preamble.Config{
		Target:     preamble.Target{Host: host, Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	}
}

func parseReq(t *testing.T, raw string) *httpwire.Request {
	t.Helper()
	req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	return req
}

func send(t *testing.T, cfg *preamble.Config, req *httpwire.Request) *Result {
	t.Helper()
	c := NewCache(time.Minute)
	t.Cleanup(c.Close)
	client, err := c.Get(cfg)
	if err != nil {
		t.Fatalf("cache.Get: %v", err)
	}
	res, err := Send(client, cfg, req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	return res
}

func TestSendDialsThePreambleTargetNotTheHostHeader(t *testing.T) {
	var gotHost string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("ok"))
	}))

	// The Host header names somewhere else entirely. The request must still
	// reach the test server, with Host passed through untouched.
	req := parseReq(t, "GET /p HTTP/1.1\r\nHost: decoy.invalid\r\n\r\n")
	res := send(t, cfg, req)

	if res.Code != 200 {
		t.Fatalf("Code = %d, want 200 (the request did not reach the target)", res.Code)
	}
	if gotHost != "decoy.invalid" {
		t.Errorf("server saw Host %q, want the original %q passed through", gotHost, "decoy.invalid")
	}
}

func TestSendPreservesHeaderOrder(t *testing.T) {
	var order []string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go's HTTP/2 server exposes the received order via this unexported-ish
		// path only for HTTP/1.1; assert on what we can see reliably instead.
		for _, k := range []string{"X-One", "X-Two", "X-Three"} {
			if r.Header.Get(k) != "" {
				order = append(order, k)
			}
		}
		w.Write([]byte("ok"))
	}))

	req := parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\nX-Three: 3\r\nX-One: 1\r\nX-Two: 2\r\n\r\n")
	if got := req.OrderedNames(); got[1] != "x-three" {
		t.Fatalf("parser lost order before sending: %v", got)
	}
	res := send(t, cfg, req)
	if res.Code != 200 {
		t.Fatalf("Code = %d", res.Code)
	}
	if len(order) != 3 {
		t.Errorf("not all headers arrived: %v", order)
	}
}

func TestSendDoesNotDecompressTheBody(t *testing.T) {
	// The server returns gzip. The helper must hand the bytes back untouched so
	// Content-Encoding still describes them.
	gz := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	} // gzip("hello")
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(gz)
	}))

	req := parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n")
	res := send(t, cfg, req)

	if string(res.Body) == "hello" {
		t.Fatal("body was decompressed; Content-Encoding would then be a lie")
	}
	if len(res.Body) != len(gz) {
		t.Errorf("Body length = %d, want the %d compressed bytes", len(res.Body), len(gz))
	}
	var sawEncoding bool
	for _, h := range res.Headers {
		if strings.EqualFold(h.Name, "Content-Encoding") && h.Value == "gzip" {
			sawEncoding = true
		}
	}
	if !sawEncoding {
		t.Error("Content-Encoding: gzip missing from the returned headers")
	}
}

func TestSendCarriesRequestBody(t *testing.T) {
	var got string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(201)
	}))

	req := parseReq(t, "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello world")
	res := send(t, cfg, req)

	if res.Code != 201 {
		t.Errorf("Code = %d, want 201", res.Code)
	}
	if got != "hello world" {
		t.Errorf("server received body %q", got)
	}
}

func TestSendReturnsDuplicateResponseHeaders(t *testing.T) {
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Write([]byte("ok"))
	}))

	res := send(t, cfg, parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	var n int
	for _, h := range res.Headers {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("got %d Set-Cookie headers, want 2", n)
	}
}

func TestSendSurfacesDialFailures(t *testing.T) {
	cfg := &preamble.Config{
		// Port 1 on loopback refuses connections.
		Target:     preamble.Target{Host: "127.0.0.1", Port: 1, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 5,
	}
	c := NewCache(time.Minute)
	defer c.Close()
	client, err := c.Get(cfg)
	if err != nil {
		t.Fatalf("cache.Get: %v", err)
	}
	if _, err := Send(client, cfg, parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")); err == nil {
		t.Error("want an error when the target refuses the connection")
	}
}

```

- [ ] **Step 6: Run it to verify it fails**

Run: `cd helper && go test ./internal/forward/ -run Send`
Expected: build failure — `undefined: Send`, `undefined: Result`.

- [ ] **Step 7: Write the forwarder**

`helper/internal/forward/forward.go`:
```go
package forward

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

// Result is an upstream answer, read fully into memory.
type Result struct {
	Code    int
	Reason  string
	Headers []httpwire.Header
	Body    []byte
}

// headers that are meaningless or illegal once the request is re-framed.
var hopByHop = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"content-length":    true, // the client sets this from the actual body
}

// Send re-sends req to the configured target and reads the whole response.
//
// The destination comes from cfg, never from the Host header, which is passed
// through untouched so the target sees exactly what the client sent.
func Send(client tls_client.HttpClient, cfg *preamble.Config, req *httpwire.Request) (*Result, error) {
	scheme := "http"
	if cfg.Target.TLS {
		scheme = "https"
	}

	// Opaque carries the request-target verbatim, so no library re-encodes it.
	u := &url.URL{Scheme: scheme, Host: cfg.Addr(), Opaque: req.Target}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	out, err := fhttp.NewRequest(req.Method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("forward: build request: %w", err)
	}
	out.URL = u
	out.Host = req.Get("Host")

	out.Header = make(fhttp.Header)
	var order []string
	for _, h := range req.Headers {
		lower := strings.ToLower(h.Name)
		if hopByHop[lower] {
			continue
		}
		out.Header[lower] = append(out.Header[lower], h.Value)
		order = append(order, lower)
	}
	// tls-client matches this key case-sensitively against lowercase names.
	out.Header[fhttp.HeaderOrderKey] = order

	res, err := client.Do(out)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	defer res.Body.Close()

	payload, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("forward: read response body: %w", err)
	}

	result := &Result{
		Code:   res.StatusCode,
		Reason: reasonOf(res.Status, res.StatusCode),
		Body:   payload,
	}
	for name := range res.Header {
		for _, v := range res.Header.Values(name) {
			result.Headers = append(result.Headers, httpwire.Header{Name: name, Value: v})
		}
	}
	return result, nil
}

// reasonOf recovers the reason phrase from "404 Not Found".
func reasonOf(status string, code int) string {
	prefix := fmt.Sprintf("%d ", code)
	if strings.HasPrefix(status, prefix) {
		return status[len(prefix):]
	}
	return fhttp.StatusText(code)
}
```

Note on response header order: `res.Header` is a map, so the order the server sent is already lost by
this point. Spec section 12 records that as a known limitation.

- [ ] **Step 8: Run the forwarding tests to verify they pass**

Run: `cd helper && go test ./internal/forward/ -v`
Expected: all tests PASS. If `TestSendPreservesHeaderOrder` fails because the profile negotiated HTTP/2
against `httptest.NewTLSServer` (which serves HTTP/1.1 only), that is fine — the assertion is only that
all three headers arrive; the wire-level order check lives in Task 19.

- [ ] **Step 9: Commit**

```bash
git add helper/internal/forward/
git commit -m "feat(helper): profiled TLS client cache and request forwarding"
```

---

### Task 9: Connection handler — keep-alive loop and error framing

Owns **Review Focus items 2 and 4**: EOF-framed responses must terminate, and the connection must stay
correctly framed after an error.

**Files:**
- Modify: `helper/internal/forward/forward.go` (add `Handle`)
- Test: `helper/internal/forward/handle_test.go`

**Interfaces:**
- Consumes: everything from Task 8, plus `preamble.Read` and `httpwire.WriteError`.
- Produces: `forward.Handle(conn net.Conn, token string, cache *Cache, relay RelayFunc, logf func(string, ...any))`
  and `forward.RelayFunc = func(conn net.Conn, cfg *preamble.Config, req *httpwire.Request) error`

- [ ] **Step 1: Write the failing test**

`helper/internal/forward/handle_test.go`:
```go
package forward

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

const testToken = "testtoken0123456789"

// dialHandled runs Handle against one end of a pipe and returns the other end.
func dialHandled(t *testing.T, relay RelayFunc) (net.Conn, *Cache) {
	t.Helper()
	client, server := net.Pipe()
	cache := NewCache(time.Minute)
	t.Cleanup(func() { cache.Close(); client.Close() })
	go Handle(server, testToken, cache, relay, func(string, ...any) {})
	return client, cache
}

func writePreamble(t *testing.T, w io.Writer, cfg *preamble.Config) {
	t.Helper()
	cfg.Token = testToken
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal preamble: %v", err)
	}
	if _, err := fmt.Fprintf(w, "%s%s\n", preamble.Magic, b); err != nil {
		t.Fatalf("write preamble: %v", err)
	}
}

func targetConfig(t *testing.T, h http.Handler) *preamble.Config {
	t.Helper()
	_, cfg := tlsServer(t, h)
	return cfg
}

func TestHandleServesTwoRequestsOnOneConnection(t *testing.T) {
	var hits int
	cfg := targetConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprintf(w, "hit%d", hits)
	}))

	conn, _ := dialHandled(t, nil)
	writePreamble(t, conn, cfg)

	br := bufio.NewReader(conn)
	for i := 1; i <= 2; i++ {
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if got, want := string(body), fmt.Sprintf("hit%d", i); got != want {
			t.Errorf("response %d body = %q, want %q", i, got, want)
		}
	}
	if hits != 2 {
		t.Errorf("target saw %d requests, want 2 — the connection was not reused", hits)
	}
}

func TestHandleKeepsConnectionUsableAfterAnErrorResponse(t *testing.T) {
	// First target refuses; the second request on the same connection targets a
	// live server only if Handle left the stream correctly framed.
	bad := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 1, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 5,
	}

	conn, _ := dialHandled(t, nil)
	writePreamble(t, conn, bad)

	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()

	if res.StatusCode != 502 {
		t.Errorf("StatusCode = %d, want 502", res.StatusCode)
	}
	if res.Header.Get("X-Awesome-Tls-Error") == "" {
		t.Error("want X-Awesome-Tls-Error on the error response")
	}
	if !strings.Contains(string(body), "Awesome TLS") {
		t.Errorf("body = %q, want the helper's error text", body)
	}
	// The response must be fully framed: ReadResponse succeeding and the body
	// terminating proves the client is not left waiting for more bytes.
}

func TestHandleRejectsABadToken(t *testing.T) {
	conn, _ := dialHandled(t, nil)
	cfg := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
		Token:      "wrong-token",
	}
	b, _ := json.Marshal(cfg)
	fmt.Fprintf(conn, "%s%s\n", preamble.Magic, b)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("want the connection closed with no reply when the token is wrong")
	}
}

func TestHandleRejectsAMissingPreamble(t *testing.T) {
	conn, _ := dialHandled(t, nil)
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("want the connection closed when no preamble is sent")
	}
}

func TestHandleReturns504OnTimeout(t *testing.T) {
	cfg := targetConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	cfg.TimeoutSec = 1

	conn, _ := dialHandled(t, nil)
	writePreamble(t, conn, cfg)
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 504 {
		t.Errorf("StatusCode = %d, want 504", res.StatusCode)
	}
}

func TestHandleHandsUpgradeRequestsToTheRelay(t *testing.T) {
	var relayed *httpwire.Request
	done := make(chan struct{})
	relay := func(conn net.Conn, cfg *preamble.Config, req *httpwire.Request) error {
		relayed = req
		close(done)
		return nil
	}

	conn, _ := dialHandled(t, relay)
	writePreamble(t, conn, &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	})
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay was not invoked for an Upgrade request")
	}
	if relayed.Target != "/ws" {
		t.Errorf("relay received target %q", relayed.Target)
	}
}

func TestHandleReadsResponseFramedOnlyByConnectionClose(t *testing.T) {
	// A raw TLS server that answers without Content-Length or
	// Transfer-Encoding, then closes: HTTP/1.0-style EOF framing.
	ln := newRawTLSServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.Read(buf)
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclosed-framed")
		c.Close()
	})

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	conn, _ := dialHandled(t, nil)
	writePreamble(t, conn, &preamble.Config{
		Target:     preamble.Target{Host: host, Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 10,
	})
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if string(body) != "closed-framed" {
		t.Errorf("body = %q, want %q", body, "closed-framed")
	}
	if res.ContentLength != int64(len("closed-framed")) {
		t.Errorf("ContentLength = %d, want %d — an exact length must be computed",
			res.ContentLength, len("closed-framed"))
	}
}
```

Add the raw TLS server helper at the end of `forward_test.go`, and add `"crypto/tls"` to that file's
imports:
```go
// newRawTLSServer serves a self-signed TLS listener whose connections are
// handled by fn, for responses net/http cannot produce.
func newRawTLSServer(t *testing.T, fn func(net.Conn)) net.Listener {
	t.Helper()
	// Borrow httptest's certificate by starting and immediately reusing its config.
	probe := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cfg := probe.TLS.Clone()
	probe.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(c)
		}
	}()
	return ln
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd helper && go test ./internal/forward/ -run Handle`
Expected: build failure — `undefined: Handle`, `undefined: RelayFunc`.

- [ ] **Step 3: Append `Handle` to `forward.go`**

```go
// RelayFunc takes over a connection for an Upgrade handshake.
type RelayFunc func(conn net.Conn, cfg *preamble.Config, req *httpwire.Request) error

// Handle serves one forward connection: read the preamble once, then serve
// requests until the peer goes away.
//
// Errors reaching the target become HTTP error responses so they are visible in
// Caido's history. Errors in the preamble or in framing close the connection,
// because at that point no well-formed reply is possible.
func Handle(conn net.Conn, token string, cache *Cache, relay RelayFunc, logf func(string, ...any)) {
	defer conn.Close()

	br := bufio.NewReader(conn)

	cfg, err := preamble.Read(br)
	if err != nil {
		logf("preamble rejected: %v", err)
		return
	}
	if err := cfg.Validate(token); err != nil {
		logf("preamble rejected: %v", err)
		return
	}

	for {
		req, err := httpwire.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				logf("request rejected: %v", err)
			}
			return
		}

		if req.IsUpgrade {
			if relay == nil {
				_ = httpwire.WriteError(conn, 501, "Not Implemented",
					errors.New("upgrade requests are not supported"))
				return
			}
			if err := relay(conn, cfg, req); err != nil {
				logf("relay failed: %v", err)
			}
			return // the relay owns the connection from here
		}

		client, err := cache.Get(cfg)
		if err != nil {
			_ = httpwire.WriteError(conn, 502, "Bad Gateway", err)
			return
		}

		res, err := Send(client, cfg, req)
		if err != nil {
			code, reason := 502, "Bad Gateway"
			if isTimeout(err) {
				code, reason = 504, "Gateway Timeout"
			}
			// WriteError sets Connection: close, so the stream ends here cleanly
			// rather than leaving the client waiting for a further request.
			_ = httpwire.WriteError(conn, code, reason, err)
			return
		}

		if err := httpwire.WriteResponse(conn, res.Code, res.Reason, res.Headers, res.Body,
			httpwire.BodyAllowed(req.Method, res.Code)); err != nil {
			logf("write response: %v", err)
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// tls-client surfaces its own deadline as a plain string.
	return strings.Contains(strings.ToLower(err.Error()), "timeout") ||
		strings.Contains(strings.ToLower(err.Error()), "deadline exceeded")
}
```

Extend `forward.go`'s imports with `"bufio"`, `"errors"` and `"net"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd helper && go test ./internal/forward/ -v`
Expected: all tests PASS. `TestHandleReturns504OnTimeout` takes a few seconds.

- [ ] **Step 5: Commit**

```bash
git add helper/internal/forward/
git commit -m "feat(helper): connection handler with keep-alive, error framing and relay dispatch"
```

---

### Task 10: Upgrade / WebSocket relay

Browsers use HTTP/1.1 for WebSockets, so the relay offers only `http/1.1` in ALPN while keeping the
rest of the ClientHello intact, then copies bytes untouched.

**Files:**
- Create: `helper/internal/relay/relay.go`
- Test: `helper/internal/relay/relay_test.go`

**Interfaces:**
- Consumes: `preamble.Config`, `httpwire.Request`, `fingerprint.Lookup`/`SpecFromHex`.
- Produces: `relay.Relay(client net.Conn, cfg *preamble.Config, req *httpwire.Request) error`, matching `forward.RelayFunc`.

- [ ] **Step 1: Write the failing test**

`helper/internal/relay/relay_test.go`:
```go
package relay

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

// echoUpgradeServer accepts a raw TLS connection, replies 101, then echoes.
func echoUpgradeServer(t *testing.T) (*preamble.Config, func() []string) {
	t.Helper()

	probe := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsCfg := probe.TLS.Clone()
	probe.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	negotiated := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return
					}
					negotiated <- tc.ConnectionState().NegotiatedProtocol
				}
				br := bufio.NewReader(c)
				// Read the upgrade request.
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				io.Copy(c, br) // echo everything after the handshake
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	drain := func() []string {
		var out []string
		for {
			select {
			case p := <-negotiated:
				out = append(out, p)
			case <-time.After(200 * time.Millisecond):
				return out
			}
		}
	}

	return &preamble.Config{
		Target:     preamble.Target{Host: host, Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	}, drain
}

func upgradeRequest(t *testing.T) *httpwire.Request {
	t.Helper()
	raw := "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	return req
}

func TestRelayCompletesTheUpgradeAndPipesBothDirections(t *testing.T) {
	cfg, drain := echoUpgradeServer(t)
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		if err := Relay(server, cfg, upgradeRequest(t)); err != nil {
			t.Logf("Relay returned: %v", err)
		}
	}()

	br := bufio.NewReader(client)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("StatusCode = %d, want 101", res.StatusCode)
	}

	// Post-handshake bytes must survive untouched in both directions.
	payload := []byte{0x81, 0x03, 'a', 'b', 'c'}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got := make([]byte, len(payload))
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo = % x, want % x", got, payload)
	}

	if protos := drain(); len(protos) == 0 || protos[0] != "http/1.1" {
		t.Errorf("negotiated ALPN = %v, want http/1.1 — browsers do not use h2 for WebSockets", protos)
	}
}

func TestRelayFailsClosedWhenTheTargetIsUnreachable(t *testing.T) {
	cfg := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 1, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 3,
	}
	client, server := net.Pipe()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- Relay(server, cfg, upgradeRequest(t)) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("want an error when the target refuses the connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not return")
	}
}

func TestRelayRejectsAnUnknownProfile(t *testing.T) {
	cfg := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "netscape_4",
		TimeoutSec: 3,
	}
	client, server := net.Pipe()
	defer client.Close()
	if err := Relay(server, cfg, upgradeRequest(t)); err == nil {
		t.Error("want an error for an unknown profile")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd helper && go test ./internal/relay/`
Expected: build failure — `undefined: Relay`.

- [ ] **Step 3: Write the implementation**

`helper/internal/relay/relay.go`:
```go
// Package relay carries Upgrade handshakes (WebSockets) through untouched,
// under the same ClientHello the forwarder would use.
//
// Rebuilding the request, as package forward does, would destroy the exact
// framing these protocols need, so this path copies bytes instead.
package relay

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/bogdanfinn/utls"

	"github.com/json/caido-awesome-tls/helper/internal/fingerprint"
	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

// Relay owns client for the rest of its life: it dials the target, replays the
// original request bytes and then copies in both directions until either side
// closes. It does not close client; the caller's defer does.
func Relay(client net.Conn, cfg *preamble.Config, req *httpwire.Request) error {
	spec, err := specFor(cfg)
	if err != nil {
		return err
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	raw, err := net.DialTimeout("tcp", cfg.Addr(), timeout)
	if err != nil {
		return fmt.Errorf("relay: dial %s: %w", cfg.Addr(), err)
	}
	defer raw.Close()

	var upstream net.Conn = raw
	if cfg.Target.TLS {
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         cfg.ServerName(),
			InsecureSkipVerify: true,
		}, utls.HelloCustom, false, true, true)
		if err := uconn.ApplyPreset(spec); err != nil {
			return fmt.Errorf("relay: apply client hello: %w", err)
		}
		if err := uconn.Handshake(); err != nil {
			return fmt.Errorf("relay: tls handshake with %s: %w", cfg.Addr(), err)
		}
		defer uconn.Close()
		upstream = uconn
	}

	// Replay the handshake request exactly as the client wrote it.
	if _, err := upstream.Write(req.Head); err != nil {
		return fmt.Errorf("relay: write upgrade request: %w", err)
	}
	if len(req.Body) > 0 {
		if _, err := upstream.Write(req.Body); err != nil {
			return fmt.Errorf("relay: write body: %w", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyThenHalfClose(upstream, client) }()
	go func() { defer wg.Done(); copyThenHalfClose(client, upstream) }()
	wg.Wait()
	return nil
}

// specFor builds the ClientHello for this connection, forcing ALPN to
// http/1.1.
//
// The fork's own forceHttp1 flag only rewrites ALPN for named presets, not for
// HelloCustom specs, so the rewrite happens here for both cases.
func specFor(cfg *preamble.Config) (*utls.ClientHelloSpec, error) {
	var spec *utls.ClientHelloSpec

	if cfg.ClientHello != "" {
		s, err := fingerprint.SpecFromHex(cfg.ClientHello)
		if err != nil {
			return nil, err
		}
		spec = s
	} else {
		profile, ok := fingerprint.Lookup(cfg.Profile)
		if !ok {
			return nil, fmt.Errorf("relay: unknown profile %q", cfg.Profile)
		}
		s, err := profile.GetClientHelloSpec()
		if err != nil {
			return nil, fmt.Errorf("relay: build client hello for %q: %w", cfg.Profile, err)
		}
		spec = &s
	}

	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	return spec, nil
}

// copyThenHalfClose copies until EOF, then signals the writer side so the peer
// sees a clean close rather than waiting for a timeout.
func copyThenHalfClose(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = dst.Close()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd helper && go test ./internal/relay/ -v`
Expected: all three tests PASS. If `TestRelayCompletesTheUpgradeAndPipesBothDirections` reports an
empty negotiated protocol, the server certificate's config had no `NextProtos`; add
`tlsCfg.NextProtos = []string{"http/1.1"}` to the test server before listening.

- [ ] **Step 5: Commit**

```bash
git add helper/internal/relay/
git commit -m "feat(helper): byte-exact Upgrade/WebSocket relay over the spoofed ClientHello"
```

---

### Task 11: ClientHello capture

Owns **Review Focus item 5**: plaintext HTTP through the capture listener must not stall.

**Files:**
- Create: `helper/internal/capture/sniff.go`, `helper/internal/capture/listener.go`
- Test: `helper/internal/capture/sniff_test.go`, `helper/internal/capture/listener_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `capture.Sniff(r io.Reader) ([]byte, error)` — returns the first complete ClientHello record, or `capture.ErrNoHello` at EOF
  - `capture.Listener`, `capture.Start(listen, forwardTo string, onHello func([]byte)) (*Listener, error)`
  - `(*Listener).Addr() string`, `(*Listener).Close() error`

- [ ] **Step 1: Write the failing sniffer test**

`helper/internal/capture/sniff_test.go`:
```go
package capture

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// helloRecord builds a TLS handshake record of the given payload length.
func helloRecord(payloadLen int) []byte {
	payload := make([]byte, payloadLen)
	payload[0] = 0x01 // handshake type: client_hello
	n := payloadLen - 4
	payload[1], payload[2], payload[3] = byte(n>>16), byte(n>>8), byte(n)
	for i := 4; i < payloadLen; i++ {
		payload[i] = byte(i % 251)
	}
	rec := []byte{0x16, 0x03, 0x01, byte(payloadLen >> 8), byte(payloadLen)}
	return append(rec, payload...)
}

func TestSniffFindsTheHelloAfterAConnectPreamble(t *testing.T) {
	hello := helloRecord(512)
	stream := append([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"), hello...)

	got, err := Sniff(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Errorf("got %d bytes, want the %d-byte record", len(got), len(hello))
	}
}

// oneByteReader delivers a single byte per Read, the worst case for a reader
// that assumes Read fills its buffer.
type oneByteReader struct{ b []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	p[0] = r.b[0]
	r.b = r.b[1:]
	return 1, nil
}

func TestSniffSurvivesSingleByteReads(t *testing.T) {
	hello := helloRecord(700)
	got, err := Sniff(&oneByteReader{b: append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...)})
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Errorf("got %d bytes, want %d — a partial read truncated the hello",
			len(got), len(hello))
	}
}

func TestSniffReturnsErrNoHelloOnPlaintextHTTP(t *testing.T) {
	// Review Focus 5: a browser proxying a plain HTTP site sends no ClientHello.
	// Sniff must finish at EOF rather than block.
	plain := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"

	done := make(chan error, 1)
	go func() {
		_, err := Sniff(strings.NewReader(plain))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNoHello) {
			t.Errorf("err = %v, want ErrNoHello", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sniff blocked on a stream containing no ClientHello")
	}
}

func TestSniffIgnoresAByteThatMerelyLooksLikeARecordHeader(t *testing.T) {
	// 0x16 inside the CONNECT line, followed by bytes that are not a plausible
	// handshake, must not be mistaken for a record.
	hello := helloRecord(300)
	noise := []byte{0x16, 0xff, 0xff, 0x00, 0x05, 0x99, 0x99, 0x99, 0x99, 0x99}
	got, err := Sniff(bytes.NewReader(append(noise, hello...)))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Errorf("sniffer locked onto noise instead of the real hello")
	}
}

func TestSniffRejectsATruncatedRecord(t *testing.T) {
	hello := helloRecord(512)
	if _, err := Sniff(bytes.NewReader(hello[:100])); err == nil {
		t.Error("want an error for a record that ends early")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd helper && go test ./internal/capture/`
Expected: build failure — `undefined: Sniff`.

- [ ] **Step 3: Write the sniffer**

`helper/internal/capture/sniff.go`:
```go
// Package capture sits between the browser and Caido, passing bytes through
// untouched while recording the browser's own ClientHello.
package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrNoHello means the stream ended without a ClientHello. That is ordinary:
// a browser proxying a plaintext site never sends one.
var ErrNoHello = errors.New("capture: stream ended before a client hello")

const (
	recordTypeHandshake   = 0x16
	handshakeTypeHello    = 0x01
	maxHelloRecordPayload = 1 << 14 // TLS record limit
	minHelloRecordPayload = 4 + 2 + 32
)

// Sniff scans for the first TLS handshake record carrying a ClientHello and
// returns the complete record, header included.
//
// Every multi-byte read uses io.ReadFull: a bare Read may return fewer bytes
// than asked for, which silently truncates the hello.
func Sniff(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)

	for {
		// Resynchronize on a candidate record type byte.
		b, err := br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ErrNoHello
			}
			return nil, fmt.Errorf("capture: %w", err)
		}
		if b != recordTypeHandshake {
			continue
		}

		header, err := br.Peek(4) // version(2) + length(2)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ErrNoHello
			}
			return nil, fmt.Errorf("capture: %w", err)
		}
		if header[0] != 0x03 { // every TLS version starts 0x03xx
			continue
		}
		length := int(binary.BigEndian.Uint16(header[2:4]))
		if length < minHelloRecordPayload || length > maxHelloRecordPayload {
			continue
		}

		if _, err := br.Discard(4); err != nil {
			return nil, fmt.Errorf("capture: %w", err)
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, fmt.Errorf("capture: read record of %d bytes: %w", length, err)
		}
		if payload[0] != handshakeTypeHello {
			continue // some other handshake message; keep looking
		}

		record := make([]byte, 0, 5+length)
		record = append(record, recordTypeHandshake, header[0], header[1], header[2], header[3])
		return append(record, payload...), nil
	}
}
```

- [ ] **Step 4: Run the sniffer tests to verify they pass**

Run: `cd helper && go test ./internal/capture/ -run Sniff -v`
Expected: all five sniffer tests PASS.

- [ ] **Step 5: Write the failing listener test**

`helper/internal/capture/listener_test.go`:
```go
package capture

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// echoBackend stands in for Caido's proxy port.
func echoBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ln
}

func TestListenerPassesBytesThroughAndReportsTheHello(t *testing.T) {
	backend := echoBackend(t)

	captured := make(chan []byte, 1)
	l, err := Start("127.0.0.1:0", backend.Addr().String(), func(h []byte) {
		select {
		case captured <- h:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	hello := helloRecord(400)
	payload := append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The echo backend proves bytes reached it unmodified.
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("bytes were modified in transit; the capture path must be transparent")
	}

	select {
	case h := <-captured:
		if !bytes.Equal(h, hello) {
			t.Errorf("captured %d bytes, want %d", len(h), len(hello))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the hello was never reported")
	}
}

func TestListenerDoesNotBlockPlaintextTraffic(t *testing.T) {
	backend := echoBackend(t)

	l, err := Start("127.0.0.1:0", backend.Addr().String(), func([]byte) {
		t.Error("onHello must not fire for plaintext traffic")
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := []byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(req))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("plaintext traffic was blocked: %v", err)
	}
	if !bytes.Equal(got, req) {
		t.Error("plaintext bytes were modified")
	}
}

func TestStartRejectsABusyPortAndCloseIsIdempotent(t *testing.T) {
	backend := echoBackend(t)

	l, err := Start("127.0.0.1:0", backend.Addr().String(), func([]byte) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := Start(l.Addr(), backend.Addr().String(), func([]byte) {}); err == nil {
		t.Error("want an error when the listen address is already in use")
	}
	if err := l.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close must be a no-op, got: %v", err)
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `cd helper && go test ./internal/capture/ -run Listener`
Expected: build failure — `undefined: Start`.

- [ ] **Step 7: Write the listener**

`helper/internal/capture/listener.go`:
```go
package capture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Listener accepts browser connections, forwards them to Caido and reports the
// first ClientHello on each.
type Listener struct {
	ln        net.Listener
	forwardTo string
	onHello   func([]byte)
	closeOnce sync.Once
	closed    chan struct{}
}

func Start(listen, forwardTo string, onHello func([]byte)) (*Listener, error) {
	if onHello == nil {
		return nil, errors.New("capture: onHello is required")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("capture: listen on %s: %w", listen, err)
	}
	l := &Listener{ln: ln, forwardTo: forwardTo, onHello: onHello, closed: make(chan struct{})}
	go l.accept()
	return l, nil
}

func (l *Listener) Addr() string { return l.ln.Addr().String() }

func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.ln.Close()
	})
	return err
}

func (l *Listener) accept() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // closed, or unrecoverable
		}
		go l.handle(conn)
	}
}

func (l *Listener) handle(client net.Conn) {
	defer client.Close()

	upstream, err := net.Dial("tcp", l.forwardTo)
	if err != nil {
		return
	}
	defer upstream.Close()

	// A TeeReader lets the sniffer observe the browser's bytes while they are
	// copied onward, so the capture path stays byte-for-byte transparent.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		hello, err := Sniff(pr)
		if err != nil {
			// ErrNoHello is ordinary: plaintext traffic carries no hello.
			// Draining the rest keeps the pipe from blocking the copy.
			_, _ = io.Copy(io.Discard, pr)
			return
		}
		l.onHello(hello)
		_, _ = io.Copy(io.Discard, pr)
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, io.TeeReader(client, pw))
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}
```

- [ ] **Step 8: Run all capture tests to verify they pass**

Run: `cd helper && go test ./internal/capture/ -v`
Expected: all eight tests PASS.

If `TestListenerPassesBytesThroughAndReportsTheHello` hangs, the pipe writer is applying back pressure
because the sniffer stopped reading. Confirm both `Sniff` paths fall through to
`io.Copy(io.Discard, pr)`, and that `pw` is closed exactly once.

- [ ] **Step 9: Commit**

```bash
git add helper/internal/capture/
git commit -m "feat(helper): transparent capture listener with a partial-read-safe ClientHello sniffer"
```

---

### Task 12: Helper entrypoint and the Windows build

**Files:**
- Create: `helper/cmd/awesome-tls-helper/main.go`
- Test: `helper/cmd/awesome-tls-helper/main_test.go`

**Interfaces:**
- Consumes: every `internal` package.
- Produces: the `awesome-tls-helper` binary, whose contract is the control protocol from Task 2.

- [ ] **Step 1: Write the failing end-to-end test**

This drives the real binary over its stdio, which is exactly how the plugin uses it.

`helper/cmd/awesome-tls-helper/main_test.go`:
```go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type helper struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	ready  map[string]any
}

// startHelper builds and runs the helper for the host platform.
func startHelper(t *testing.T) *helper {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "helper")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	cmd := exec.Command(bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	h := &helper{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdoutPipe)}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })

	h.ready = h.expect(t, "ready", 10*time.Second)
	return h
}

// expect reads control messages until one of the wanted type arrives.
func (h *helper) expect(t *testing.T, want string, timeout time.Duration) map[string]any {
	t.Helper()
	type result struct {
		m   map[string]any
		err error
	}
	ch := make(chan result, 1)
	go func() {
		for {
			line, err := h.stdout.ReadString('\n')
			if err != nil {
				ch <- result{err: err}
				return
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				continue
			}
			if m["type"] == want {
				ch <- result{m: m}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("waiting for %q: %v", want, r.err)
		}
		return r.m
	case <-timeout2chan(timeout):
		t.Fatalf("timed out waiting for a %q message", want)
		return nil
	}
}

func timeout2chan(d time.Duration) <-chan time.Time { return time.After(d) }

func (h *helper) send(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}
	if _, err := h.stdin.Write(append(b, '\n')); err != nil {
		t.Fatalf("write command: %v", err)
	}
}

func TestReadyAnnouncesPortTokenAndProfiles(t *testing.T) {
	h := startHelper(t)

	port, ok := h.ready["port"].(float64)
	if !ok || port <= 0 {
		t.Fatalf("ready.port = %v", h.ready["port"])
	}
	token, ok := h.ready["token"].(string)
	if !ok || len(token) < 32 {
		t.Errorf("ready.token = %q, want at least 32 hex characters", token)
	}
	profiles, ok := h.ready["profiles"].([]any)
	if !ok || len(profiles) < 20 {
		t.Errorf("ready.profiles has %d entries", len(profiles))
	}
	if d, _ := h.ready["defaultProfile"].(string); d == "" {
		t.Error("ready.defaultProfile is empty")
	}

	// The forward listener must be loopback-only.
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", int(port)), 2*time.Second); err != nil {
		t.Errorf("forward listener not reachable on loopback: %v", err)
	}
}

func TestForwardsARequestThroughTheHelper(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		fmt.Fprint(w, "forwarded")
	}))
	defer target.Close()

	h := startHelper(t)
	port := int(h.ready["port"].(float64))
	token := h.ready["token"].(string)

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))
	var tport int
	fmt.Sscanf(portStr, "%d", &tport)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial helper: %v", err)
	}
	defer conn.Close()

	pre := map[string]any{
		"token":      token,
		"target":     map[string]any{"host": host, "port": tport, "tls": true},
		"sni":        nil,
		"profile":    h.ready["defaultProfile"],
		"clientHello": nil,
		"timeoutSec": 30,
	}
	b, _ := json.Marshal(pre)
	fmt.Fprintf(conn, "AWESOMETLS/1 %s\n", b)
	io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: decoy.invalid\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != 200 || string(body) != "forwarded" {
		t.Errorf("status=%d body=%q", res.StatusCode, body)
	}
	if got := res.Header.Get("X-Seen-Host"); got != "decoy.invalid" {
		t.Errorf("target saw Host %q, want the original passed through", got)
	}
}

func TestCaptureCommandStartsAndStopsTheListener(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	h := startHelper(t)

	h.send(t, map[string]any{
		"type": "capture", "enabled": true,
		"listen": "127.0.0.1:0", "forwardTo": backend.Addr().String(),
	})
	st := h.expect(t, "capture-status", 5*time.Second)
	if st["state"] != "listening" {
		t.Fatalf("capture state = %v, want listening (error: %v)", st["state"], st["error"])
	}
	listen, _ := st["listen"].(string)
	if listen == "" {
		t.Fatal("capture-status.listen is empty; the chosen port must be reported")
	}

	conn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("dial capture listener: %v", err)
	}
	defer conn.Close()

	hello := buildTestHello(600)
	conn.Write(append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...))

	cap := h.expect(t, "captured", 5*time.Second)
	if s, _ := cap["clientHello"].(string); len(s) != len(hello)*2 {
		t.Errorf("captured hello hex length = %d, want %d", len(s), len(hello)*2)
	}
	if s, _ := cap["ja4"].(string); !strings.Contains(s, "_") {
		t.Errorf("captured.ja4 = %q, want a JA4 string", s)
	}

	h.send(t, map[string]any{"type": "capture", "enabled": false})
	if st := h.expect(t, "capture-status", 5*time.Second); st["state"] != "stopped" {
		t.Errorf("capture state = %v, want stopped", st["state"])
	}
}

func TestExitsWhenStdinCloses(t *testing.T) {
	h := startHelper(t)

	if err := h.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not exit when stdin closed; it would outlive the plugin")
	}
}

// buildTestHello produces a minimal ClientHello that the fingerprint parser
// accepts: version, random, no session, two ciphers, null compression, and an
// SNI extension.
func buildTestHello(pad int) []byte {
	var exts bytes.Buffer
	name := "example.com"
	sni := []byte{0x00}
	sni = append(sni, byte(len(name)>>8), byte(len(name)))
	sni = append(sni, name...)
	exts.Write([]byte{0x00, 0x00, byte((len(sni) + 2) >> 8), byte(len(sni) + 2),
		byte(len(sni) >> 8), byte(len(sni))})
	exts.Write(sni)
	// Padding extension to reach a realistic size.
	if pad > exts.Len()+8 {
		n := pad - exts.Len() - 8
		exts.Write([]byte{0x00, 0x15, byte(n >> 8), byte(n)})
		exts.Write(make([]byte, n))
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x04, 0x13, 0x01, 0x13, 0x02})
	body.Write([]byte{0x01, 0x00})
	body.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	body.Write(exts.Bytes())

	hs := []byte{0x01, byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())}
	hs = append(hs, body.Bytes()...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd helper && go test ./cmd/awesome-tls-helper/`
Expected: build failure — `main.go` does not exist yet.

- [ ] **Step 3: Write `main.go`**

`helper/cmd/awesome-tls-helper/main.go`:
```go
// Command awesome-tls-helper forwards HTTP requests with a chosen browser's
// TLS and HTTP/2 fingerprint.
//
// It is started by the Caido plugin and speaks a JSON-lines protocol over
// stdio. It holds no configuration of its own: every forward connection carries
// its own settings, so a restart loses nothing. Closing its stdin shuts it down.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/capture"
	"github.com/json/caido-awesome-tls/helper/internal/control"
	"github.com/json/caido-awesome-tls/helper/internal/fingerprint"
	"github.com/json/caido-awesome-tls/helper/internal/forward"
	"github.com/json/caido-awesome-tls/helper/internal/relay"
)

const version = "0.1.0"

// captureThrottle collapses bursts: a browser opens many connections and each
// one carries the same hello.
const captureThrottle = 2 * time.Second

func main() {
	out := control.NewWriter(os.Stdout)

	token, err := newToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate token: %v\n", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	cache := forward.NewCache(10 * time.Minute)
	defer cache.Close()

	go evictLoop(cache)

	cm := &captureManager{out: out}
	defer cm.stop()

	if err := out.Emit(control.Ready{
		Type:           "ready",
		Port:           ln.Addr().(*net.TCPAddr).Port,
		Token:          token,
		Profiles:       fingerprint.Profiles(),
		DefaultProfile: fingerprint.DefaultProfile(),
		Version:        version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "emit ready: %v\n", err)
		os.Exit(1)
	}

	go accept(ln, token, cache, out)

	// Returning from ReadCommands means stdin closed: the plugin is gone.
	if err := control.ReadCommands(os.Stdin, cm.handle); err != nil {
		fmt.Fprintf(os.Stderr, "read commands: %v\n", err)
	}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func accept(ln net.Listener, token string, cache *forward.Cache, out *control.Writer) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go forward.Handle(conn, token, cache, relay.Relay, func(format string, args ...any) {
			out.Logf("warn", format, args...)
		})
	}
}

func evictLoop(cache *forward.Cache) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		cache.Evict(time.Now())
	}
}

// captureManager owns the optional capture listener.
type captureManager struct {
	mu       sync.Mutex
	out      *control.Writer
	listener *capture.Listener
	lastHex  string
	lastAt   time.Time
}

func (m *captureManager) handle(c control.Command) {
	if c.Type != "capture" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listener != nil {
		_ = m.listener.Close()
		m.listener = nil
	}
	if !c.Enabled {
		_ = m.out.Emit(control.CaptureStatus{Type: "capture-status", State: "stopped"})
		return
	}

	l, err := capture.Start(c.Listen, c.ForwardTo, m.onHello)
	if err != nil {
		_ = m.out.Emit(control.CaptureStatus{
			Type: "capture-status", State: "error", Listen: c.Listen, Error: err.Error(),
		})
		return
	}
	m.listener = l
	_ = m.out.Emit(control.CaptureStatus{
		Type: "capture-status", State: "listening", Listen: l.Addr(),
	})
}

func (m *captureManager) onHello(raw []byte) {
	encoded := hex.EncodeToString(raw)

	m.mu.Lock()
	if encoded == m.lastHex || time.Since(m.lastAt) < captureThrottle {
		m.mu.Unlock()
		return
	}
	m.lastHex, m.lastAt = encoded, time.Now()
	m.mu.Unlock()

	info, err := fingerprint.Analyze(raw)
	if err != nil {
		_ = m.out.Emit(control.CaptureRejected{Type: "capture-rejected", Error: err.Error()})
		return
	}
	// Confirm the hello is replayable before offering it as a fingerprint.
	if _, err := fingerprint.SpecFromRaw(raw); err != nil {
		_ = m.out.Emit(control.CaptureRejected{
			Type: "capture-rejected", Error: err.Error(), JA4: info.JA4,
		})
		return
	}
	_ = m.out.Emit(control.Captured{
		Type:        "captured",
		ClientHello: encoded,
		JA3:         info.JA3,
		JA3Text:     info.JA3Text,
		JA4:         info.JA4,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
	})
}

func (m *captureManager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener != nil {
		_ = m.listener.Close()
		m.listener = nil
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd helper && go test ./cmd/awesome-tls-helper/ -v`
Expected: all four tests PASS.

Note on throttling: `TestCaptureCommandStartsAndStopsTheListener` sends one hello, so the throttle never
engages. If a later test needs two in quick succession, they must differ or be spaced beyond
`captureThrottle`.

- [ ] **Step 5: Verify the full helper suite and vet**

Run: `cd helper && go vet ./... && go test ./...`
Expected: no vet findings; every package PASSes.

- [ ] **Step 6: Cross-compile for Windows and confirm the flags**

Run from the repo root:
```bash
pnpm build:helper
ls -la packages/backend/assets/bin/awesome-tls-helper.exe
file packages/backend/assets/bin/awesome-tls-helper.exe
```
Expected: a `PE32+ executable (GUI) x86-64` of roughly 12-18 MB. `(GUI)` confirms `-H windowsgui`; a
`(console)` binary would flash a window on every spawn.

- [ ] **Step 7: Commit**

```bash
git add helper/cmd/
git commit -m "feat(helper): entrypoint wiring listeners, cache and capture to the control protocol"
```

---

## Phase 2 — Backend plugin

### Task 13: Settings

**Files:**
- Create: `packages/backend/src/settings.ts`, `packages/backend/src/settings.test.ts`
- Create: `packages/backend/tsconfig.json`, `packages/backend/vitest.config.ts`
- Modify: `packages/backend/package.json` (test script already added in Task 1)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type FingerprintSource = "preset" | "captured"`
  - `type CapturedHello = { clientHello: string; ja3: string; ja4: string; capturedAt: string }`
  - `type Settings = { source: FingerprintSource; profile: string; timeoutSec: number; capture: { enabled: boolean; listen: string; forwardTo: string; last: CapturedHello | null } }`
  - `const DEFAULTS: Settings`
  - `validate(raw: unknown, opts: { profiles: string[]; fallbackProfile: string }): { settings: Settings; warnings: string[] }`
  - `class SettingsStore { constructor(path: string); load(opts): Promise<string[]>; get(): Settings; update(patch: DeepPartial<Settings>, opts): Promise<string[]>; }`

- [ ] **Step 1: Add the TypeScript and test configuration**

`packages/backend/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "skipLibCheck": true,
    "noEmit": true,
    "types": ["@caido/sdk-backend", "@caido/quickjs-types"]
  },
  "include": ["src/**/*.ts"]
}
```

`packages/backend/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
```

- [ ] **Step 2: Write the failing test**

`packages/backend/src/settings.test.ts`:
```ts
import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DEFAULTS, SettingsStore, validate } from "./settings";

const opts = { profiles: ["chrome_150", "firefox_148"], fallbackProfile: "chrome_150" };

describe("validate", () => {
  it("returns the defaults for absent input", () => {
    const { settings, warnings } = validate(undefined, opts);
    expect(settings).toEqual(DEFAULTS);
    expect(warnings).toEqual([]);
  });

  it("accepts a fully specified object unchanged", () => {
    const input = {
      source: "captured",
      profile: "firefox_148",
      timeoutSec: 45,
      capture: {
        enabled: true,
        listen: "127.0.0.1:9000",
        forwardTo: "127.0.0.1:8080",
        last: { clientHello: "16030100", ja3: "a".repeat(32), ja4: "t13d1516h2_aaa_bbb", capturedAt: "2026-10-03T00:00:00Z" },
      },
    };
    const { settings, warnings } = validate(input, opts);
    expect(settings).toEqual(input);
    expect(warnings).toEqual([]);
  });

  it("falls back and warns when the profile is unknown", () => {
    const { settings, warnings } = validate({ profile: "netscape_4" }, opts);
    expect(settings.profile).toBe("chrome_150");
    expect(warnings.join(" ")).toContain("netscape_4");
  });

  it("clamps an out-of-range timeout", () => {
    expect(validate({ timeoutSec: 0 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: 10_000 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: 1.5 }, opts).settings.timeoutSec).toBe(DEFAULTS.timeoutSec);
    expect(validate({ timeoutSec: 60 }, opts).settings.timeoutSec).toBe(60);
  });

  it("rejects a non-loopback capture address", () => {
    const { settings, warnings } = validate(
      { capture: { listen: "0.0.0.0:8886" } }, opts);
    expect(settings.capture.listen).toBe(DEFAULTS.capture.listen);
    expect(warnings.join(" ")).toContain("loopback");
  });

  it("rejects a malformed capture address", () => {
    for (const bad of ["127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "nonsense"]) {
      const { settings } = validate({ capture: { forwardTo: bad } }, opts);
      expect(settings.capture.forwardTo, bad).toBe(DEFAULTS.capture.forwardTo);
    }
  });

  it("accepts localhost and ::1 as loopback", () => {
    expect(validate({ capture: { listen: "localhost:8886" } }, opts).settings.capture.listen)
      .toBe("localhost:8886");
    expect(validate({ capture: { listen: "[::1]:8886" } }, opts).settings.capture.listen)
      .toBe("[::1]:8886");
  });

  it("drops a captured hello that is not hex", () => {
    const { settings, warnings } = validate(
      { capture: { last: { clientHello: "zzz", ja3: "x", ja4: "y", capturedAt: "z" } } }, opts);
    expect(settings.capture.last).toBeNull();
    expect(warnings.join(" ")).toContain("hex");
  });

  it("ignores an unknown source value", () => {
    expect(validate({ source: "telepathy" }, opts).settings.source).toBe(DEFAULTS.source);
  });

  it("survives hostile shapes without throwing", () => {
    for (const bad of [null, 42, "string", [], { capture: 7 }, { capture: { last: 1 } }]) {
      expect(() => validate(bad, opts)).not.toThrow();
    }
  });
});

describe("SettingsStore", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "awesome-tls-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("starts from the defaults when no file exists", async () => {
    const store = new SettingsStore(join(dir, "settings.json"));
    const warnings = await store.load(opts);
    expect(warnings).toEqual([]);
    expect(store.get()).toEqual(DEFAULTS);
  });

  it("persists an update and reloads it", async () => {
    const path = join(dir, "settings.json");
    const store = new SettingsStore(path);
    await store.load(opts);

    await store.update({ profile: "firefox_148", timeoutSec: 45 }, opts);
    expect(store.get().profile).toBe("firefox_148");
    expect(store.get().timeoutSec).toBe(45);

    const reloaded = new SettingsStore(path);
    await reloaded.load(opts);
    expect(reloaded.get().profile).toBe("firefox_148");
    expect(reloaded.get().timeoutSec).toBe(45);
  });

  it("merges a nested patch without dropping sibling fields", async () => {
    const store = new SettingsStore(join(dir, "settings.json"));
    await store.load(opts);
    await store.update({ capture: { enabled: true } }, opts);

    expect(store.get().capture.enabled).toBe(true);
    expect(store.get().capture.listen).toBe(DEFAULTS.capture.listen);
    expect(store.get().capture.forwardTo).toBe(DEFAULTS.capture.forwardTo);
  });

  it("recovers from a corrupt file instead of failing to start", async () => {
    const path = join(dir, "settings.json");
    writeFileSync(path, "{ this is not json");

    const store = new SettingsStore(path);
    const warnings = await store.load(opts);
    expect(store.get()).toEqual(DEFAULTS);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it("writes readable JSON", async () => {
    const path = join(dir, "settings.json");
    const store = new SettingsStore(path);
    await store.load(opts);
    await store.update({ timeoutSec: 45 }, opts);

    const parsed = JSON.parse(readFileSync(path, "utf8"));
    expect(parsed.timeoutSec).toBe(45);
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

Run: `pnpm -C packages/backend test`
Expected: failure — cannot resolve `./settings`.

- [ ] **Step 4: Write the implementation**

`packages/backend/src/settings.ts`:
```ts
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
  profile: "chrome_150",
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
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};

const MIN_TIMEOUT = 1;
const MAX_TIMEOUT = 600;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Loopback only: the helper must never be reachable from the network. */
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function splitHostPort(addr: string): { host: string; port: number } | null {
  const match = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(addr);
  if (!match) return null;
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
  if (!parts) {
    warnings.push(`${field}: "${value}" is not host:port; using ${fallback}`);
    return fallback;
  }
  if (!LOOPBACK.has(parts.host)) {
    warnings.push(
      `${field}: "${parts.host}" is not a loopback address; using ${fallback}`,
    );
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
  if (clientHello.length === 0 || clientHello.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clientHello)) {
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

  let profile = DEFAULTS.profile;
  if (typeof input.profile === "string" && input.profile !== "") {
    // An empty profile list means the helper has not reported yet; accept the
    // stored value rather than silently rewriting it.
    if (opts.profiles.length === 0 || opts.profiles.includes(input.profile)) {
      profile = input.profile;
    } else {
      warnings.push(`profile: "${input.profile}" is not available; using ${opts.fallbackProfile}`);
      profile = opts.fallbackProfile;
    }
  } else if (opts.fallbackProfile !== "") {
    profile = opts.fallbackProfile;
  }

  let timeoutSec = DEFAULTS.timeoutSec;
  if (typeof input.timeoutSec === "number") {
    if (Number.isInteger(input.timeoutSec) &&
        input.timeoutSec >= MIN_TIMEOUT && input.timeoutSec <= MAX_TIMEOUT) {
      timeoutSec = input.timeoutSec;
    } else {
      warnings.push(
        `timeoutSec: ${input.timeoutSec} is outside ${MIN_TIMEOUT}-${MAX_TIMEOUT}; using ${DEFAULTS.timeoutSec}`,
      );
    }
  }

  return {
    settings: {
      source,
      profile,
      timeoutSec,
      capture: {
        enabled: typeof captureInput.enabled === "boolean"
          ? captureInput.enabled
          : DEFAULTS.capture.enabled,
        listen: validateAddress(
          captureInput.listen, DEFAULTS.capture.listen, "capture.listen", warnings),
        forwardTo: validateAddress(
          captureInput.forwardTo, DEFAULTS.capture.forwardTo, "capture.forwardTo", warnings),
        last: validateCapturedHello(captureInput.last, warnings),
      },
    },
    warnings,
  };
}

function merge(base: Settings, patch: DeepPartial<Settings>): unknown {
  return {
    ...base,
    ...patch,
    capture: { ...base.capture, ...(patch.capture ?? {}) },
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
      if (code === "ENOENT") {
        const { settings } = validate(undefined, opts);
        this.settings = settings;
        return [];
      }
      // A corrupt file must not stop the plugin from loading.
      const { settings } = validate(undefined, opts);
      this.settings = settings;
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm -C packages/backend test`
Expected: every test PASSes.

- [ ] **Step 6: Commit**

```bash
git add packages/backend/
git commit -m "feat(backend): settings schema, validation and JSON persistence"
```

---

### Task 14: Helper process manager

**Files:**
- Create: `packages/backend/src/helper.ts`, `packages/backend/src/helper.test.ts`

**Interfaces:**
- Consumes: `CapturedHello` (Task 13).
- Produces:
  - `type HelperState = { kind: "starting" } | { kind: "running"; port: number; profiles: string[]; defaultProfile: string; version: string } | { kind: "restarting"; attempt: number; error: string } | { kind: "failed"; error: string } | { kind: "stopped" }`
  - `type CaptureState = { state: "listening" | "stopped" | "error"; listen?: string; error?: string }`
  - `type Spawner = (exe: string) => ChildHandle` — injected so tests need no real process
  - `type ChildHandle = { stdout: AsyncIterable<string> | NodeJS.EventEmitter; ... }` — see code
  - `class HelperManager` with `start()`, `stop()`, `restart()`, `sendCapture(enabled, listen, forwardTo)`, `state()`, `endpoint()`, `profiles()`
  - `BACKOFF_MS`, `MAX_FAILURES`, `FAILURE_WINDOW_MS`, `READY_TIMEOUT_MS`

- [ ] **Step 1: Write the failing test**

`packages/backend/src/helper.test.ts`:
```ts
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

import {
  BACKOFF_MS,
  HelperManager,
  MAX_FAILURES,
  READY_TIMEOUT_MS,
  type ChildHandle,
} from "./helper";

/** A scriptable stand-in for the helper process. */
class FakeChild extends EventEmitter implements ChildHandle {
  readonly written: string[] = [];
  killed = false;
  readonly stdout = new EventEmitter();
  readonly stderr = new EventEmitter();

  write(line: string): void {
    this.written.push(line);
  }
  kill(): void {
    this.killed = true;
    this.emit("exit", 0);
  }
  closeStdin(): void {
    this.emit("stdin-closed");
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

  const manager = new HelperManager({
    exe: "C:/fake/awesome-tls-helper.exe",
    spawn: spawner,
    onState: (s) => states.push(s),
    onCaptured: (c) => captured.push(c),
    onCaptureState: (s) => captureStates.push(s),
    log: () => {},
  });

  return { manager, children, spawner, states, captured, captureStates };
}

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { vi.useRealTimers(); });

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
  });

  it("never exposes the token through the public state", async () => {
    const { manager, children, states } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    // endpoint() is internal and does carry the token; the state stream must not.
    expect(JSON.stringify(states)).not.toContain("t".repeat(64));
    const state = manager.state();
    expect(JSON.stringify(state)).not.toContain("t".repeat(64));
  });

  it("fails when ready never arrives", async () => {
    const { manager } = setup();
    const started = manager.start();
    await vi.advanceTimersByTimeAsync(READY_TIMEOUT_MS + 100);
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

    for (let i = 0; i < MAX_FAILURES; i++) {
      children[children.length - 1]!.emit("exit", 1);
      await vi.advanceTimersByTimeAsync((BACKOFF_MS[Math.min(i, BACKOFF_MS.length - 1)] ?? 0) + 10);
      const latest = children[children.length - 1]!;
      if (latest !== children[0]) latest.readyNow();
      await vi.advanceTimersByTimeAsync(10);
    }
    children[children.length - 1]!.emit("exit", 1);
    await vi.advanceTimersByTimeAsync(60_000);

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
  });

  it("forwards capture commands and surfaces capture state", async () => {
    const { manager, children, captureStates } = setup();
    const started = manager.start();
    children[0]!.readyNow();
    await started;

    manager.sendCapture(true, "127.0.0.1:8886", "127.0.0.1:8080");
    expect(children[0]!.written.join("")).toContain('"type":"capture"');
    expect(children[0]!.written.join("")).toContain('"listen":"127.0.0.1:8886"');

    children[0]!.say({ type: "capture-status", state: "listening", listen: "127.0.0.1:8886" });
    await vi.advanceTimersByTimeAsync(10);
    expect(captureStates.at(-1)).toMatchObject({ state: "listening", listen: "127.0.0.1:8886" });
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
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm -C packages/backend test helper`
Expected: failure — cannot resolve `./helper`.

- [ ] **Step 3: Write the implementation**

`packages/backend/src/helper.ts`:
```ts
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

  /** Internal: carries the auth token, so it must not reach the frontend. */
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
    if (this.child) {
      // Closing stdin is the helper's documented shutdown signal; kill is the
      // fallback if it does not take the hint.
      this.child.closeStdin();
      this.child.kill();
      this.child = null;
    }
    this.point = null;
    this.setState({ kind: "stopped" });
  }

  async restart(): Promise<void> {
    this.failures = [];
    this.stopping = true;
    this.clearTimers();
    if (this.child) {
      this.child.closeStdin();
      this.child.kill();
      this.child = null;
    }
    this.point = null;
    this.stopping = false;
    return this.spawnChild();
  }

  sendCapture(enabled: boolean, listen: string, forwardTo: string): void {
    this.send({ type: "capture", enabled, listen, forwardTo });
  }

  private send(msg: unknown): void {
    if (!this.child) return;
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
          if (this.child) {
            this.child.kill();
            this.child = null;
          }
        }
        this.resolveReady();
      }, READY_TIMEOUT_MS);
    });
  }

  private resolveReady(): void {
    const resolve = this.readyResolve;
    this.readyResolve = null;
    if (this.readyTimer) {
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
          typeof clientHello === "string" && typeof ja3 === "string" &&
          typeof ja4 === "string" && typeof capturedAt === "string"
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
    this.point = null;
    this.resolveReady();

    if (this.stopping) return;

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
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }
    if (this.readyTimer) {
      clearTimeout(this.readyTimer);
      this.readyTimer = null;
    }
  }

  private setState(state: HelperState): void {
    this.current = state;
    this.opts.onState(state);
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm -C packages/backend test helper`
Expected: all eleven tests PASS.

If `gives up after repeated rapid failures` is brittle because of the ready/exit interleaving, simplify
it to: ready once, then emit `exit` `MAX_FAILURES + 1` times with
`await vi.advanceTimersByTimeAsync(31_000)` between each, and assert the final state is `failed`.

- [ ] **Step 5: Commit**

```bash
git add packages/backend/src/helper.ts packages/backend/src/helper.test.ts
git commit -m "feat(backend): helper process supervisor with restart backoff"
```

---

### Task 15: Preamble builder and the upstream hook

**Files:**
- Create: `packages/backend/src/preamble.ts`, `packages/backend/src/preamble.test.ts`, `packages/backend/src/upstream.ts`
- Test: `packages/backend/src/upstream.test.ts`

**Interfaces:**
- Consumes: `Settings` (Task 13), `HelperManager` (Task 14).
- Produces:
  - `buildPreamble(args: PreambleArgs): Uint8Array`
  - `type PreambleArgs = { token: string; host: string; port: number; tls: boolean; sni: string | null; profile: string; clientHello: string | null; timeoutSec: number }`
  - `preambleArgsFor(settings: Settings, token: string, info: { host: string; port: number; tls: boolean; sni?: string }): PreambleArgs`
  - `registerUpstream(sdk, deps: { helper: HelperManager; settings: { get(): Settings } }): void`

- [ ] **Step 1: Write the failing preamble test**

`packages/backend/src/preamble.test.ts`:
```ts
import { describe, expect, it } from "vitest";

import { buildPreamble, preambleArgsFor } from "./preamble";
import { DEFAULTS, type Settings } from "./settings";

const args = {
  token: "abc123",
  host: "example.com",
  port: 443,
  tls: true,
  sni: null,
  profile: "chrome_150",
  clientHello: null,
  timeoutSec: 30,
};

function decode(bytes: Uint8Array): { magic: string; json: Record<string, unknown> } {
  const text = new TextDecoder().decode(bytes);
  expect(text.endsWith("\n")).toBe(true);
  const space = text.indexOf(" ");
  return {
    magic: text.slice(0, space + 1),
    json: JSON.parse(text.slice(space + 1, -1)) as Record<string, unknown>,
  };
}

describe("buildPreamble", () => {
  it("emits the magic prefix, one JSON object and a trailing newline", () => {
    const { magic, json } = decode(buildPreamble(args));
    expect(magic).toBe("AWESOMETLS/1 ");
    expect(json).toEqual({
      token: "abc123",
      target: { host: "example.com", port: 443, tls: true },
      sni: null,
      profile: "chrome_150",
      clientHello: null,
      timeoutSec: 30,
    });
  });

  it("contains exactly one newline, at the very end", () => {
    const text = new TextDecoder().decode(buildPreamble(args));
    expect(text.split("\n")).toHaveLength(2);
    expect(text.indexOf("\n")).toBe(text.length - 1);
  });

  it("carries an SNI override and a captured hello when given", () => {
    const { json } = decode(buildPreamble({
      ...args, sni: "other.example", clientHello: "160301aa",
    }));
    expect(json.sni).toBe("other.example");
    expect(json.clientHello).toBe("160301aa");
  });

  it("encodes a non-ASCII host as UTF-8 without a stray newline", () => {
    const bytes = buildPreamble({ ...args, host: "xn--caf-dma.example" });
    const { json } = decode(bytes);
    expect(json.target).toMatchObject({ host: "xn--caf-dma.example" });
  });

  it("rejects a token containing a newline, which would forge a second line", () => {
    expect(() => buildPreamble({ ...args, token: "abc\ndef" })).toThrow();
  });
});

describe("preambleArgsFor", () => {
  it("uses the preset profile and no hello when the source is preset", () => {
    const settings: Settings = { ...DEFAULTS, source: "preset", profile: "firefox_148" };
    const got = preambleArgsFor(settings, "tok",
      { host: "h.example", port: 8443, tls: true });

    expect(got.profile).toBe("firefox_148");
    expect(got.clientHello).toBeNull();
    expect(got).toMatchObject({ host: "h.example", port: 8443, tls: true, sni: null });
  });

  it("supplies the captured hello when the source is captured", () => {
    const settings: Settings = {
      ...DEFAULTS,
      source: "captured",
      capture: {
        ...DEFAULTS.capture,
        last: { clientHello: "160301ff", ja3: "x", ja4: "y", capturedAt: "z" },
      },
    };
    const got = preambleArgsFor(settings, "tok", { host: "h", port: 443, tls: true });
    expect(got.clientHello).toBe("160301ff");
    // The profile still travels: it supplies the HTTP/2 layer.
    expect(got.profile).toBe(settings.profile);
  });

  it("falls back to the preset when captured is selected but nothing was captured", () => {
    const settings: Settings = { ...DEFAULTS, source: "captured" };
    expect(preambleArgsFor(settings, "tok", { host: "h", port: 443, tls: true }).clientHello)
      .toBeNull();
  });

  it("passes an SNI override through", () => {
    const got = preambleArgsFor(DEFAULTS, "tok",
      { host: "h", port: 443, tls: true, sni: "sni.example" });
    expect(got.sni).toBe("sni.example");
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm -C packages/backend test preamble`
Expected: failure — cannot resolve `./preamble`.

- [ ] **Step 3: Write `preamble.ts`**

```ts
/**
 * Builds the out-of-band configuration line written at the start of every
 * forward connection. The line must be exactly one newline-terminated JSON
 * object, because the helper reads up to the first newline.
 */
import type { Settings } from "./settings";

export const MAGIC = "AWESOMETLS/1 ";

export type PreambleArgs = {
  token: string;
  host: string;
  port: number;
  tls: boolean;
  sni: string | null;
  profile: string;
  clientHello: string | null;
  timeoutSec: number;
};

export function buildPreamble(args: PreambleArgs): Uint8Array {
  const payload = {
    token: args.token,
    target: { host: args.host, port: args.port, tls: args.tls },
    sni: args.sni,
    profile: args.profile,
    clientHello: args.clientHello,
    timeoutSec: args.timeoutSec,
  };

  const json = JSON.stringify(payload);
  // JSON.stringify escapes newlines inside strings, so a literal newline here
  // would mean the serializer failed us; refuse rather than send a split line.
  if (json.includes("\n")) {
    throw new Error("preamble: serialized configuration contains a newline");
  }
  if (args.token.includes("\n") || args.token.includes("\r")) {
    throw new Error("preamble: token contains a line break");
  }

  return new TextEncoder().encode(MAGIC + json + "\n");
}

/** Chooses the fingerprint for this request from the current settings. */
export function preambleArgsFor(
  settings: Settings,
  token: string,
  info: { host: string; port: number; tls: boolean; sni?: string | undefined },
): PreambleArgs {
  const captured =
    settings.source === "captured" ? settings.capture.last?.clientHello ?? null : null;

  return {
    token,
    host: info.host,
    port: info.port,
    tls: info.tls,
    sni: info.sni ?? null,
    // The profile travels even with a captured hello: it supplies the HTTP/2
    // layer, which a ClientHello says nothing about.
    profile: settings.profile,
    clientHello: captured,
    timeoutSec: settings.timeoutSec,
  };
}
```

- [ ] **Step 4: Run the preamble tests to verify they pass**

Run: `pnpm -C packages/backend test preamble`
Expected: all nine tests PASS.

- [ ] **Step 5: Write the failing upstream test**

`packages/backend/src/upstream.test.ts`:
```ts
import { describe, expect, it, vi } from "vitest";

import { makeUpstreamHandler } from "./upstream";
import { DEFAULTS, type Settings } from "./settings";

type FakeConn = { send: ReturnType<typeof vi.fn>; receive: ReturnType<typeof vi.fn> };

function fakeSdk(conn: FakeConn) {
  return {
    net: { connect: vi.fn(async () => conn) },
    console: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
}

function fakeRequest(info: { host: string; port: number; tls: boolean; sni?: string }) {
  return { getInfo: () => ({ ...info, sni: info.sni }) };
}

function deps(overrides: {
  endpoint?: { port: number; token: string } | null;
  settings?: Settings;
} = {}) {
  const endpoint = overrides.endpoint === undefined
    ? { port: 51234, token: "tok" }
    : overrides.endpoint;
  return {
    helper: {
      endpoint: () => endpoint,
      state: () => ({ kind: "running" as const, port: 51234, profiles: [], defaultProfile: "", version: "" }),
    },
    settings: { get: () => overrides.settings ?? DEFAULTS },
    log: vi.fn(),
  };
}

describe("upstream handler", () => {
  it("returns a loopback connection with the preamble already written", async () => {
    const conn: FakeConn = { send: vi.fn(async () => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    const handler = makeUpstreamHandler(deps());

    const result = await handler(sdk as never,
      fakeRequest({ host: "example.com", port: 443, tls: true }) as never);

    expect(sdk.net.connect).toHaveBeenCalledTimes(1);
    const dialed = String(sdk.net.connect.mock.calls[0]![0]);
    expect(dialed).toContain("127.0.0.1");
    expect(dialed).toContain("51234");

    expect(conn.send).toHaveBeenCalledTimes(1);
    const sent = new TextDecoder().decode(conn.send.mock.calls[0]![0] as Uint8Array);
    expect(sent.startsWith("AWESOMETLS/1 ")).toBe(true);
    expect(sent).toContain('"host":"example.com"');
    expect(sent.endsWith("\n")).toBe(true);

    expect(result).toEqual({ connection: conn });
  });

  it("passes the target's own port and TLS flag through", async () => {
    const conn: FakeConn = { send: vi.fn(async () => {}), receive: vi.fn() };
    const handler = makeUpstreamHandler(deps());
    await handler(fakeSdk(conn) as never,
      fakeRequest({ host: "h", port: 8080, tls: false }) as never);

    const sent = new TextDecoder().decode(conn.send.mock.calls[0]![0] as Uint8Array);
    expect(sent).toContain('"port":8080');
    expect(sent).toContain('"tls":false');
  });

  it("throws when the helper is not running, so the request fails closed", async () => {
    const conn: FakeConn = { send: vi.fn(async () => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    const handler = makeUpstreamHandler(deps({ endpoint: null }));

    await expect(
      handler(sdk as never, fakeRequest({ host: "h", port: 443, tls: true }) as never),
    ).rejects.toThrow(/helper/i);

    expect(sdk.net.connect).not.toHaveBeenCalled();
  });

  it("propagates a connect failure rather than returning undefined", async () => {
    const conn: FakeConn = { send: vi.fn(async () => {}), receive: vi.fn() };
    const sdk = fakeSdk(conn);
    sdk.net.connect = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const handler = makeUpstreamHandler(deps());

    await expect(
      handler(sdk as never, fakeRequest({ host: "h", port: 443, tls: true }) as never),
    ).rejects.toThrow();
  });

  it("propagates a preamble write failure", async () => {
    const conn: FakeConn = {
      send: vi.fn(async () => { throw new Error("broken pipe"); }),
      receive: vi.fn(),
    };
    const handler = makeUpstreamHandler(deps());

    await expect(
      handler(fakeSdk(conn) as never, fakeRequest({ host: "h", port: 443, tls: true }) as never),
    ).rejects.toThrow(/broken pipe/);
  });

  it("never logs the token", async () => {
    const conn: FakeConn = { send: vi.fn(async () => {}), receive: vi.fn() };
    const d = deps({ endpoint: { port: 51234, token: "SUPERSECRET" } });
    const handler = makeUpstreamHandler(d);
    await handler(fakeSdk(conn) as never, fakeRequest({ host: "h", port: 443, tls: true }) as never);

    expect(JSON.stringify(d.log.mock.calls)).not.toContain("SUPERSECRET");
  });
});
```

- [ ] **Step 6: Run it to verify it fails**

Run: `pnpm -C packages/backend test upstream`
Expected: failure — cannot resolve `./upstream`.

- [ ] **Step 7: Write `upstream.ts`**

```ts
/**
 * The onUpstream hook: hands Caido a loopback connection to the helper with the
 * per-request configuration already written to it.
 *
 * This path is on the request hot path, so it does no I/O beyond one connect
 * and one write.
 */
import type { SDK } from "caido:plugin";
import type { Connection, RequestSpecRaw } from "caido:utils";

import { buildPreamble, preambleArgsFor } from "./preamble";
import type { Settings } from "./settings";

export type UpstreamDeps = {
  helper: {
    endpoint: () => { port: number; token: string } | null;
    state: () => { kind: string };
  };
  settings: { get(): Settings };
  log: (level: "info" | "warn" | "error", msg: string) => void;
};

export function makeUpstreamHandler(deps: UpstreamDeps) {
  return async function onUpstream(
    sdk: Pick<SDK, "net" | "console">,
    request: Pick<RequestSpecRaw, "getInfo">,
  ): Promise<{ connection: Connection }> {
    const endpoint = deps.helper.endpoint();
    if (endpoint === null) {
      // Fail closed. Returning undefined would let Caido send the request with
      // its own fingerprint, silently defeating the plugin.
      throw new Error(
        `Awesome TLS: helper is not running (${deps.helper.state().kind}); request blocked`,
      );
    }

    const info = request.getInfo();
    const args = preambleArgsFor(deps.settings.get(), endpoint.token, {
      host: info.host,
      port: info.port,
      tls: info.tls,
      sni: info.sni,
    });

    const connection = await sdk.net.connect(`tcp://127.0.0.1:${endpoint.port}`);
    await connection.send(buildPreamble(args));
    return { connection };
  };
}

/** Registers the hook with Caido. */
export function registerUpstream(sdk: SDK, deps: UpstreamDeps): void {
  const handler = makeUpstreamHandler(deps);
  sdk.events.onUpstream(async (eventSdk, request) => handler(eventSdk, request));
}
```

**Probe dependency:** Task 1 recorded which form `sdk.net.connect` accepts. If `tcp://host:port` was
rejected, replace the connect call with a `ConnectionInfo` whose `tls` is `false`, and update
the two `expect(dialed)` assertions in `upstream.test.ts` accordingly.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `pnpm -C packages/backend test`
Expected: every backend test PASSes.

- [ ] **Step 9: Commit**

```bash
git add packages/backend/src/preamble.ts packages/backend/src/preamble.test.ts \
        packages/backend/src/upstream.ts packages/backend/src/upstream.test.ts
git commit -m "feat(backend): preamble builder and fail-closed onUpstream hook"
```

---

### Task 16: Routing rules, RPC API and backend wiring

**Files:**
- Create: `packages/backend/src/routing.ts`, `packages/backend/src/routing.test.ts`
- Modify: `packages/backend/src/index.ts` (replace the Task 1 stub)

**Interfaces:**
- Consumes: everything from Tasks 13-15.
- Produces:
  - `findBackendPluginId(execute, manifestId): Promise<string | null>`
  - `readRule(execute, pluginId): Promise<UpstreamRule | null>`
  - `enableForAllDomains(execute, manifestId): Promise<UpstreamRule>`
  - `type UpstreamRule = { id: string; enabled: boolean; allowlist: string[]; denylist: string[] }`
  - `type StateDTO = { helper: HelperState; capture: CaptureState; settings: Settings; routing: UpstreamRule | null; warnings: string[] }`
  - `export type API = DefineAPI<{ getState, updateSettings, restartHelper, clearCapture, enableRouting }>`
  - backend event `"state"` carrying `StateDTO`

- [ ] **Step 1: Write the failing routing test**

`packages/backend/src/routing.test.ts`:
```ts
import { describe, expect, it, vi } from "vitest";

import { enableForAllDomains, findBackendPluginId, readRule } from "./routing";

/** A GraphQL executor that answers from a script of responses. */
function executor(responses: unknown[]) {
  const calls: { query: string; variables?: Record<string, unknown> }[] = [];
  const execute = vi.fn(async (query: string, variables?: Record<string, unknown>) => {
    calls.push({ query, variables });
    return responses.shift() ?? { data: {} };
  });
  return { execute, calls };
}

describe("findBackendPluginId", () => {
  it("matches on manifestId and the backend typename", async () => {
    const { execute } = executor([
      { data: { plugins: [
        { __typename: "PluginFrontend", id: "1", manifestId: "awesome-tls-frontend" },
        { __typename: "PluginBackend", id: "42", manifestId: "awesome-tls-backend" },
      ] } },
    ]);

    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBe("42");
  });

  it("returns null when no plugin matches", async () => {
    const { execute } = executor([{ data: { plugins: [] } }]);
    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBeNull();
  });

  it("returns null when the query errors instead of throwing", async () => {
    const { execute } = executor([{ errors: [{ message: "nope" }] }]);
    expect(await findBackendPluginId(execute, "awesome-tls-backend")).toBeNull();
  });
});

describe("readRule", () => {
  it("returns the rule belonging to this plugin", async () => {
    const { execute } = executor([
      { data: { upstreamPlugins: [
        { id: "9", enabled: true, allowlist: ["*"], denylist: [], plugin: { id: "7" } },
        { id: "10", enabled: false, allowlist: ["a.example"], denylist: [], plugin: { id: "42" } },
      ] } },
    ]);

    expect(await readRule(execute, "42")).toEqual({
      id: "10", enabled: false, allowlist: ["a.example"], denylist: [],
    });
  });

  it("returns null when this plugin has no rule", async () => {
    const { execute } = executor([{ data: { upstreamPlugins: [] } }]);
    expect(await readRule(execute, "42")).toBeNull();
  });
});

describe("enableForAllDomains", () => {
  it("creates a wildcard rule when none exists", async () => {
    const { execute, calls } = executor([
      { data: { plugins: [{ __typename: "PluginBackend", id: "42", manifestId: "awesome-tls-backend" }] } },
      { data: { upstreamPlugins: [] } },
      { data: { createUpstreamPlugin: { upstream: {
        id: "11", enabled: true, allowlist: ["*"], denylist: [], plugin: { id: "42" },
      } } } },
    ]);

    const rule = await enableForAllDomains(execute, "awesome-tls-backend");
    expect(rule).toMatchObject({ enabled: true, allowlist: ["*"] });

    const mutation = calls.at(-1)!;
    expect(mutation.query).toContain("createUpstreamPlugin");
    expect(mutation.variables).toEqual({
      input: { pluginId: "42", allowlist: ["*"], denylist: [], enabled: true },
    });
  });

  it("updates an existing rule rather than creating a second one", async () => {
    const { execute, calls } = executor([
      { data: { plugins: [{ __typename: "PluginBackend", id: "42", manifestId: "awesome-tls-backend" }] } },
      { data: { upstreamPlugins: [
        { id: "10", enabled: false, allowlist: ["old.example"], denylist: [], plugin: { id: "42" } },
      ] } },
      { data: { updateUpstreamPlugin: { upstream: {
        id: "10", enabled: true, allowlist: ["*"], denylist: [], plugin: { id: "42" },
      } } } },
    ]);

    const rule = await enableForAllDomains(execute, "awesome-tls-backend");
    expect(rule).toMatchObject({ id: "10", enabled: true, allowlist: ["*"] });
    expect(calls.at(-1)!.query).toContain("updateUpstreamPlugin");
  });

  it("throws a clear error when the plugin id cannot be resolved", async () => {
    const { execute } = executor([{ data: { plugins: [] } }]);
    await expect(enableForAllDomains(execute, "awesome-tls-backend"))
      .rejects.toThrow(/plugin id/i);
  });

  it("throws when the mutation reports errors", async () => {
    const { execute } = executor([
      { data: { plugins: [{ __typename: "PluginBackend", id: "42", manifestId: "awesome-tls-backend" }] } },
      { data: { upstreamPlugins: [] } },
      { errors: [{ message: "forbidden" }] },
    ]);
    await expect(enableForAllDomains(execute, "awesome-tls-backend"))
      .rejects.toThrow(/forbidden/);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm -C packages/backend test routing`
Expected: failure — cannot resolve `./routing`.

- [ ] **Step 3: Write `routing.ts`**

```ts
/**
 * Reads and writes Caido's own Upstream Plugins rules over GraphQL, so the
 * plugin page can offer a one-click "route everything through me".
 *
 * Finer-grained rules stay in Caido's settings; this module only implements the
 * wildcard shortcut and reports the current rule.
 */

export type UpstreamRule = {
  id: string;
  enabled: boolean;
  allowlist: string[];
  denylist: string[];
};

export type GraphQLExecute = <T>(
  query: string,
  variables?: Record<string, unknown>,
) => Promise<{ data?: T; errors?: { message: string }[] }>;

const PLUGINS_QUERY = `
  query awesomeTlsPlugins {
    plugins { __typename id manifestId }
  }
`;

const RULES_QUERY = `
  query awesomeTlsUpstreamPlugins {
    upstreamPlugins { id enabled allowlist denylist plugin { id } }
  }
`;

const CREATE_MUTATION = `
  mutation awesomeTlsCreateUpstream($input: CreateUpstreamPluginInput!) {
    createUpstreamPlugin(input: $input) {
      upstream { id enabled allowlist denylist plugin { id } }
    }
  }
`;

const UPDATE_MUTATION = `
  mutation awesomeTlsUpdateUpstream($id: ID!, $input: UpdateUpstreamPluginInput!) {
    updateUpstreamPlugin(id: $id, input: $input) {
      upstream { id enabled allowlist denylist plugin { id } }
    }
  }
`;

type PluginRow = { __typename?: string; id: string; manifestId: string };
type RuleRow = UpstreamRule & { plugin: { id: string } };

function firstError(res: { errors?: { message: string }[] }): string | null {
  return res.errors?.[0]?.message ?? null;
}

/** Resolves this plugin's Caido-internal id, which the rule mutations need. */
export async function findBackendPluginId(
  execute: GraphQLExecute,
  manifestId: string,
): Promise<string | null> {
  const res = await execute<{ plugins: PluginRow[] }>(PLUGINS_QUERY);
  if (firstError(res) !== null) return null;

  const match = (res.data?.plugins ?? []).find(
    (p) => p.manifestId === manifestId && p.__typename !== "PluginFrontend",
  );
  return match?.id ?? null;
}

export async function readRule(
  execute: GraphQLExecute,
  pluginId: string,
): Promise<UpstreamRule | null> {
  const res = await execute<{ upstreamPlugins: RuleRow[] }>(RULES_QUERY);
  if (firstError(res) !== null) return null;

  const row = (res.data?.upstreamPlugins ?? []).find((r) => r.plugin.id === pluginId);
  if (row === undefined) return null;
  return {
    id: row.id,
    enabled: row.enabled,
    allowlist: row.allowlist,
    denylist: row.denylist,
  };
}

/**
 * Points every domain at this plugin, updating an existing rule in place so
 * repeated clicks cannot pile up duplicates.
 */
export async function enableForAllDomains(
  execute: GraphQLExecute,
  manifestId: string,
): Promise<UpstreamRule> {
  const pluginId = await findBackendPluginId(execute, manifestId);
  if (pluginId === null) {
    throw new Error(
      `Awesome TLS: could not resolve the plugin id for "${manifestId}"; ` +
      `add the rule manually under Settings > Upstream > Upstream Plugins`,
    );
  }

  const existing = await readRule(execute, pluginId);
  const input = { pluginId, allowlist: ["*"], denylist: [], enabled: true };

  if (existing === null) {
    const res = await execute<{ createUpstreamPlugin: { upstream: RuleRow | null } }>(
      CREATE_MUTATION, { input });
    const err = firstError(res);
    if (err !== null) throw new Error(`Awesome TLS: ${err}`);
    const upstream = res.data?.createUpstreamPlugin.upstream;
    if (!upstream) throw new Error("Awesome TLS: Caido created no upstream rule");
    return strip(upstream);
  }

  const res = await execute<{ updateUpstreamPlugin: { upstream: RuleRow | null } }>(
    UPDATE_MUTATION, { id: existing.id, input });
  const err = firstError(res);
  if (err !== null) throw new Error(`Awesome TLS: ${err}`);
  const upstream = res.data?.updateUpstreamPlugin.upstream;
  if (!upstream) throw new Error("Awesome TLS: Caido returned no upstream rule");
  return strip(upstream);
}

function strip(row: RuleRow): UpstreamRule {
  return {
    id: row.id,
    enabled: row.enabled,
    allowlist: row.allowlist,
    denylist: row.denylist,
  };
}
```

**Schema caveat:** the exact argument shape of `updateUpstreamPlugin` (an `id` argument plus `input`,
versus `input` alone) comes from the generated SDK types. Confirm against
`node_modules/@caido/sdk-frontend/src/types/__generated__/graphql-sdk.d.ts`, searching for
`MutationRootUpdateUpstreamPluginArgs`, and adjust both the mutation and its test if it differs.

- [ ] **Step 4: Run the routing tests to verify they pass**

Run: `pnpm -C packages/backend test routing`
Expected: all eight tests PASS.

- [ ] **Step 5: Write `index.ts`**

```ts
/**
 * Plugin entrypoint: owns the lifetime of the settings store and the helper,
 * and is the only place the two meet.
 */
import type { DefineAPI, SDK } from "caido:plugin";
import { spawn } from "child_process";
import { join } from "path";

import {
  HelperManager,
  type CaptureState,
  type ChildHandle,
  type HelperState,
} from "./helper";
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

export type API = DefineAPI<{
  getState: () => StateDTO;
  updateSettings: (patch: DeepPartial<Settings>) => StateDTO;
  restartHelper: () => StateDTO;
  clearCapture: () => StateDTO;
  enableRouting: () => StateDTO;
}>;

export type BackendEvents = {
  state: (state: StateDTO) => void;
};

/** Adapts Caido's child_process to the ChildHandle the manager expects. */
function spawnHelper(exe: string): ChildHandle {
  const child = spawn(exe, { stdio: ["pipe", "pipe", "pipe"] });
  return {
    stdout: child.stdout!,
    stderr: child.stderr!,
    on: (event, cb) => child.on(event, cb as never),
    write: (line) => { child.stdin!.write(line); },
    kill: () => { child.kill(); },
    closeStdin: () => { child.stdin!.end(); },
  };
}

export function init(sdk: SDK<API, BackendEvents>) {
  const store = new SettingsStore(join(sdk.meta.path(), "settings.json"));
  let capture: CaptureState = { state: "stopped" };
  let routing: UpstreamRule | null = null;
  let warnings: string[] = [];

  const log = (level: "info" | "warn" | "error", msg: string) => {
    if (level === "error") sdk.console.error(msg);
    else if (level === "warn") sdk.console.warn(msg);
    else sdk.console.log(msg);
  };

  const validateOptions = () => ({
    profiles: helper.profiles(),
    fallbackProfile: (() => {
      const state = helper.state();
      return state.kind === "running" && state.defaultProfile !== ""
        ? state.defaultProfile
        : store.get().profile;
    })(),
  });

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
    exe: join(sdk.meta.assetsPath(), "bin", HELPER_EXE),
    spawn: spawnHelper,
    onState: (state) => {
      if (state.kind === "running") {
        // Re-validate now that the real profile list is known, and restore the
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
    onCaptureState: (state) => { capture = state; publish(); },
    onCaptured: (hello) => {
      void (async () => {
        warnings = await store.update({ capture: { last: hello } }, validateOptions());
        publish();
      })();
    },
    log,
  });

  registerUpstream(sdk, { helper, settings: store, log });

  sdk.api.register("getState", () => snapshot());

  sdk.api.register("updateSettings", async (_sdk, patch: DeepPartial<Settings>) => {
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
      routing = await enableForAllDomains(
        (query, variables) => sdk.graphql.execute(query, variables) as never,
        sdk.meta.id(),
      );
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

    const pluginId = await findBackendPluginId(
      (query, variables) => sdk.graphql.execute(query, variables) as never,
      sdk.meta.id(),
    );
    if (pluginId !== null) {
      routing = await readRule(
        (query, variables) => sdk.graphql.execute(query, variables) as never,
        pluginId,
      );
    }

    await helper.start();
    publish();
  })();
}
```

- [ ] **Step 6: Typecheck and run the whole backend suite**

Run: `pnpm -C packages/backend test && pnpm -C packages/backend typecheck`
Expected: all tests PASS and no type errors.

`init` has no unit test of its own: it is pure wiring over units that are each tested, and the behavior
that matters end to end is covered by Task 19.

- [ ] **Step 7: Commit**

```bash
git add packages/backend/
git commit -m "feat(backend): routing rule management, RPC API and plugin wiring"
```

---

## Phase 3 — Frontend

### Task 17: Plugin page with status and fingerprint cards

**Files:**
- Create: `packages/frontend/package.json`, `packages/frontend/tsconfig.json`
- Create: `packages/frontend/src/index.ts`, `packages/frontend/src/App.vue`
- Create: `packages/frontend/src/components/StatusCard.vue`, `packages/frontend/src/components/FingerprintCard.vue`

**Interfaces:**
- Consumes: the backend RPC API and the `state` event (Task 16).
- Produces: a sidebar item "Awesome TLS" at path `/awesome-tls`.

- [ ] **Step 1: Create the package**

`packages/frontend/package.json`:
```json
{
  "name": "awesome-tls-frontend",
  "version": "0.1.0",
  "type": "module",
  "main": "src/index.ts",
  "scripts": { "typecheck": "vue-tsc --noEmit" },
  "dependencies": {
    "vue": "^3.5.0"
  },
  "devDependencies": {
    "@caido/sdk-frontend": "0.58.3",
    "@types/node": "^22.0.0",
    "typescript": "^5.6.0",
    "vue-tsc": "^2.1.0"
  }
}
```

`packages/frontend/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "skipLibCheck": true,
    "noEmit": true,
    "jsx": "preserve",
    "types": ["node"]
  },
  "include": ["src/**/*.ts", "src/**/*.vue"]
}
```

- [ ] **Step 2: Write the entrypoint**

`packages/frontend/src/index.ts`:
```ts
import { createApp, type App as VueApp } from "vue";
import type { Caido } from "@caido/sdk-frontend";

import AppRoot from "./App.vue";
import type { API, BackendEvents, StateDTO } from "../../backend/src/index";

export type FrontendSDK = Caido<API, BackendEvents>;

const PATH = "/awesome-tls";

export function init(sdk: FrontendSDK) {
  const root = document.createElement("div");
  root.id = "awesome-tls-root";
  root.style.height = "100%";

  const app: VueApp = createApp(AppRoot, { sdk });
  app.mount(root);

  sdk.navigation.addPage(PATH, { body: root });
  sdk.sidebar.registerItem("Awesome TLS", PATH, { icon: "fas fa-lock" });
}

export type { StateDTO };
```

- [ ] **Step 3: Write `App.vue`**

```vue
<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";

import StatusCard from "./components/StatusCard.vue";
import FingerprintCard from "./components/FingerprintCard.vue";
import type { FrontendSDK } from "./index";
import type { StateDTO } from "../../backend/src/index";

const props = defineProps<{ sdk: FrontendSDK }>();

const state = ref<StateDTO | null>(null);
const busy = ref(false);
let unsubscribe: (() => void) | null = null;

/** Runs a backend call, keeping the page usable if it throws. */
async function call(fn: () => Promise<StateDTO>) {
  busy.value = true;
  try {
    state.value = await fn();
  } catch (err) {
    props.sdk.window.showToast(`Awesome TLS: ${String(err)}`, { variant: "error" });
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  const handler = (next: StateDTO) => { state.value = next; };
  props.sdk.backend.onEvent("state", handler);
  unsubscribe = () => props.sdk.backend.offEvent?.("state", handler);

  await call(() => props.sdk.backend.getState());
});

onUnmounted(() => unsubscribe?.());
</script>

<template>
  <div class="p-6 flex flex-col gap-4 overflow-auto h-full">
    <header>
      <h1 class="text-xl font-semibold">Awesome TLS</h1>
      <p class="text-sm opacity-70">
        Sends routed requests with a real browser's TLS and HTTP/2 fingerprint.
      </p>
    </header>

    <p v-if="state === null" class="text-sm opacity-70">Loading…</p>

    <template v-else>
      <StatusCard
        :state="state"
        :busy="busy"
        @restart="call(() => props.sdk.backend.restartHelper())"
        @enable-routing="call(() => props.sdk.backend.enableRouting())"
      />
      <FingerprintCard
        :state="state"
        :busy="busy"
        @update="(patch) => call(() => props.sdk.backend.updateSettings(patch))"
      />
      <!-- CaptureCard is added in Task 18. -->
    </template>
  </div>
</template>
```

- [ ] **Step 4: Write `StatusCard.vue`**

```vue
<script setup lang="ts">
import { computed } from "vue";
import type { StateDTO } from "../../../backend/src/index";

const props = defineProps<{ state: StateDTO; busy: boolean }>();
defineEmits<{ restart: []; "enable-routing": [] }>();

const helperLabel = computed(() => {
  const h = props.state.helper;
  switch (h.kind) {
    case "running":  return `Running on 127.0.0.1:${h.port} (helper ${h.version})`;
    case "starting": return "Starting…";
    case "restarting": return `Restarting after failure ${h.attempt}: ${h.error}`;
    case "failed":   return `Failed: ${h.error}`;
    case "stopped":  return "Stopped";
  }
});

const helperTone = computed(() => {
  switch (props.state.helper.kind) {
    case "running": return "text-green-500";
    case "failed":  return "text-red-500";
    default:        return "text-amber-500";
  }
});

const routingLabel = computed(() => {
  const r = props.state.routing;
  if (r === null) return "No routing rule: no traffic reaches this plugin yet.";
  if (!r.enabled) return "Routing rule exists but is disabled.";
  const allow = r.allowlist.length === 0 ? "(none)" : r.allowlist.join(", ");
  const deny = r.denylist.length === 0 ? "" : ` — excluding ${r.denylist.join(", ")}`;
  return `Routing ${allow}${deny}`;
});

const routingActive = computed(() => props.state.routing?.enabled === true);
</script>

<template>
  <section class="rounded border border-surface-700 p-4 flex flex-col gap-3">
    <h2 class="font-semibold">Status</h2>

    <div class="flex items-center gap-2 text-sm">
      <span class="opacity-70 w-20">Helper</span>
      <span :class="helperTone">{{ helperLabel }}</span>
      <button
        v-if="state.helper.kind === 'failed' || state.helper.kind === 'stopped'"
        class="ml-auto px-3 py-1 rounded bg-surface-700 text-sm disabled:opacity-50"
        :disabled="busy"
        @click="$emit('restart')"
      >
        Restart
      </button>
    </div>

    <div class="flex items-center gap-2 text-sm">
      <span class="opacity-70 w-20">Routing</span>
      <span :class="routingActive ? 'text-green-500' : 'text-amber-500'">{{ routingLabel }}</span>
      <button
        v-if="!routingActive"
        class="ml-auto px-3 py-1 rounded bg-primary-600 text-sm disabled:opacity-50"
        :disabled="busy"
        @click="$emit('enable-routing')"
      >
        Enable for all domains
      </button>
    </div>

    <p class="text-xs opacity-60">
      Per-domain rules live in Settings → Upstream → Upstream Plugins.
      Caido's own upstream proxy does not apply to routed traffic: the helper opens the
      outbound connection itself.
    </p>

    <ul v-if="state.warnings.length > 0" class="text-xs text-amber-500 list-disc pl-5">
      <li v-for="w in state.warnings" :key="w">{{ w }}</li>
    </ul>
  </section>
</template>
```

- [ ] **Step 5: Write `FingerprintCard.vue`**

```vue
<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { StateDTO } from "../../../backend/src/index";

const props = defineProps<{ state: StateDTO; busy: boolean }>();
const emit = defineEmits<{ update: [patch: Record<string, unknown>] }>();

const filter = ref("");
const timeout = ref(props.state.settings.timeoutSec);

watch(() => props.state.settings.timeoutSec, (v) => { timeout.value = v; });

const profiles = computed(() => {
  const all = props.state.helper.kind === "running" ? props.state.helper.profiles : [];
  const needle = filter.value.trim().toLowerCase();
  return needle === "" ? all : all.filter((p) => p.toLowerCase().includes(needle));
});

const hasCapture = computed(() => props.state.settings.capture.last !== null);
</script>

<template>
  <section class="rounded border border-surface-700 p-4 flex flex-col gap-3">
    <h2 class="font-semibold">Fingerprint</h2>

    <div class="flex gap-4 text-sm">
      <label class="flex items-center gap-2">
        <input
          type="radio" value="preset" :checked="state.settings.source === 'preset'"
          :disabled="busy" @change="emit('update', { source: 'preset' })"
        />
        Preset profile
      </label>
      <label class="flex items-center gap-2" :class="{ 'opacity-50': !hasCapture }">
        <input
          type="radio" value="captured" :checked="state.settings.source === 'captured'"
          :disabled="busy || !hasCapture" @change="emit('update', { source: 'captured' })"
        />
        Captured browser hello
      </label>
    </div>

    <p v-if="state.settings.source === 'captured'" class="text-xs opacity-60">
      The TLS hello comes from your browser; the HTTP/2 layer still comes from the profile
      below, so pick the same browser family.
    </p>

    <label class="flex flex-col gap-1 text-sm">
      <span class="opacity-70">Profile ({{ profiles.length }} available)</span>
      <input
        v-model="filter" placeholder="Filter, e.g. chrome"
        class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
      />
      <select
        class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
        :value="state.settings.profile" :disabled="busy"
        @change="emit('update', { profile: ($event.target as HTMLSelectElement).value })"
      >
        <option v-for="p in profiles" :key="p" :value="p">{{ p }}</option>
      </select>
    </label>

    <label class="flex flex-col gap-1 text-sm max-w-xs">
      <span class="opacity-70">Timeout (seconds)</span>
      <input
        v-model.number="timeout" type="number" min="1" max="600" :disabled="busy"
        class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
        @change="emit('update', { timeoutSec: timeout })"
      />
    </label>
  </section>
</template>
```

- [ ] **Step 6: Verify it builds**

Run from the repo root: `pnpm install && pnpm build`
Expected: `dist/plugin_package.zip` is produced with no Vue or TypeScript errors.

If `sdk.backend.offEvent` does not exist in this SDK version, drop the `unsubscribe` logic and leave the
listener attached for the page's lifetime; also confirm whether the event API is `sdk.backend.onEvent`
or `sdk.backend.on`, and adjust `App.vue`.

- [ ] **Step 7: Commit**

```bash
git add packages/frontend/
git commit -m "feat(frontend): plugin page with status and fingerprint cards"
```

---

### Task 18: Capture card

**Files:**
- Create: `packages/frontend/src/components/CaptureCard.vue`
- Modify: `packages/frontend/src/App.vue` (import and render it)

**Interfaces:**
- Consumes: `StateDTO` (Task 16); the `updateSettings` and `clearCapture` RPC calls.
- Produces: nothing new.

- [ ] **Step 1: Write `CaptureCard.vue`**

```vue
<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { StateDTO } from "../../../backend/src/index";

const props = defineProps<{ state: StateDTO; busy: boolean }>();
const emit = defineEmits<{ update: [patch: Record<string, unknown>]; clear: [] }>();

const listen = ref(props.state.settings.capture.listen);
const forwardTo = ref(props.state.settings.capture.forwardTo);

watch(() => props.state.settings.capture.listen, (v) => { listen.value = v; });
watch(() => props.state.settings.capture.forwardTo, (v) => { forwardTo.value = v; });

const captureLabel = computed(() => {
  const c = props.state.capture;
  switch (c.state) {
    case "listening": return `Listening on ${c.listen ?? listen.value}`;
    case "error":     return `Error: ${c.error ?? "unknown"}`;
    case "stopped":   return "Not listening";
  }
});

const captureTone = computed(() =>
  props.state.capture.state === "listening" ? "text-green-500"
    : props.state.capture.state === "error" ? "text-red-500" : "opacity-70");

const last = computed(() => props.state.settings.capture.last);
</script>

<template>
  <section class="rounded border border-surface-700 p-4 flex flex-col gap-3">
    <h2 class="font-semibold">Capture your browser's fingerprint</h2>

    <label class="flex items-center gap-2 text-sm">
      <input
        type="checkbox" :checked="state.settings.capture.enabled" :disabled="busy"
        @change="emit('update', {
          capture: { enabled: ($event.target as HTMLInputElement).checked },
        })"
      />
      Enable the capture listener
    </label>

    <p class="text-sm" :class="captureTone">{{ captureLabel }}</p>

    <div class="grid grid-cols-2 gap-3 max-w-xl text-sm">
      <label class="flex flex-col gap-1">
        <span class="opacity-70">Listen on</span>
        <input
          v-model="listen" :disabled="busy"
          class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
          @change="emit('update', { capture: { listen } })"
        />
      </label>
      <label class="flex flex-col gap-1">
        <span class="opacity-70">Forward to Caido at</span>
        <input
          v-model="forwardTo" :disabled="busy"
          class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
          @change="emit('update', { capture: { forwardTo } })"
        />
      </label>
    </div>

    <p class="text-xs opacity-60">
      Point your browser's proxy at the listen address instead of Caido. Traffic passes
      straight through while the first TLS hello is recorded. Both addresses must be loopback.
    </p>

    <div v-if="last !== null" class="text-xs flex flex-col gap-1 font-mono">
      <span class="opacity-70 font-sans">Last capture — {{ last.capturedAt }}</span>
      <span>JA3 {{ last.ja3 }}</span>
      <span>JA4 {{ last.ja4 }}</span>
      <span class="opacity-70 font-sans">{{ last.clientHello.length / 2 }} bytes</span>
      <button
        class="self-start mt-1 px-3 py-1 rounded bg-surface-700 font-sans disabled:opacity-50"
        :disabled="busy" @click="emit('clear')"
      >
        Clear
      </button>
    </div>
    <p v-else class="text-xs opacity-60">Nothing captured yet.</p>
  </section>
</template>
```

- [ ] **Step 2: Wire it into `App.vue`**

Add the import beside the other two:
```ts
import CaptureCard from "./components/CaptureCard.vue";
```

and replace the `<!-- CaptureCard is added in Task 18. -->` comment with:
```vue
      <CaptureCard
        :state="state"
        :busy="busy"
        @update="(patch) => call(() => props.sdk.backend.updateSettings(patch))"
        @clear="call(() => props.sdk.backend.clearCapture())"
      />
```

- [ ] **Step 3: Build and typecheck**

Run: `pnpm build && pnpm typecheck`
Expected: a clean build and no type errors.

- [ ] **Step 4: Verify the page in Caido**

Install `dist/plugin_package.zip` and open the Awesome TLS page. All three cards must render, the
profile dropdown must list the helper's profiles, and changing the timeout must persist across a
page switch. Full behavior is verified in Task 19.

- [ ] **Step 5: Commit**

```bash
git add packages/frontend/
git commit -m "feat(frontend): capture card"
```

---

## Phase 4 — Acceptance

### Task 19: End-to-end acceptance against Caido on Windows

This is the only task that proves the thing actually works. Everything before it is unit and
integration coverage that cannot observe a real fingerprint.

**Files:**
- Modify: `helper/internal/fingerprint/ja_test.go` (freeze the confirmed vector)
- Create: `README.md`
- Modify: `docs/superpowers/specs/2026-10-03-caido-awesome-tls-design.md` (record results)

**Interfaces:**
- Consumes: the built `dist/plugin_package.zip`.
- Produces: a confirmed-working plugin and a frozen JA3/JA4 regression vector.

- [ ] **Step 1: Build and install**

```bash
pnpm build
ls -la dist/plugin_package.zip
```

In Caido on Windows: Plugins → Install from file → the zip. Enable both components. Open the
**Awesome TLS** page and confirm the helper reports Running with a profile list.

- [ ] **Step 2: Record the baseline with the plugin off**

With no routing rule, send from Replay:
```
GET /api/all HTTP/1.1
Host: tls.peet.ws
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
```

Record `tls.ja3_hash`, `tls.ja4`, `http2.akamai_fingerprint_hash` and `http_version`. This is Caido's
native fingerprint.

- [ ] **Step 3: Enable routing and confirm the fingerprint changed**

Click **Enable for all domains**, then resend the same request.

Acceptance:
- `http_version` is `h2`.
- `tls.ja4` starts `t13d` and differs from the baseline.
- `tls.ja3_hash` differs from the baseline.
- `http2.akamai_fingerprint_hash` differs from the baseline.
- The `http2.sent_frames` `HEADERS` entry lists the request headers in the order written above, and
  `Accept-Encoding` still reads `gzip, deflate, br`.
- The response body in Caido is readable, and its `Content-Encoding` matches the bytes — this is the
  `DisableCompression` behavior from Task 8 observed end to end.

Record all four values in the spec.

- [ ] **Step 4: Confirm the profile selection has an effect**

Switch the profile to `firefox_148` and resend. `tls.ja4` and the Akamai hash must both change again.
Switch back to the Chrome profile.

- [ ] **Step 5: Freeze the JA3/JA4 regression vector**

The recorded hello in `testdata/chrome.hello` is the Chrome-150 hello the helper sends. Compare the
`t.Logf` output from `TestAnalyzeAcceptsTheRecordedChromeHello` with the `tls.ja3_hash` and `tls.ja4`
that tls.peet.ws reported in step 3.

If they match, replace the `t.Logf` with assertions:
```go
	const (
		wantJA3 = "<value confirmed in step 3>"
		wantJA4 = "<value confirmed in step 3>"
	)
	if info.JA3 != wantJA3 {
		t.Errorf("JA3 = %q, want %q", info.JA3, wantJA3)
	}
	if info.JA4 != wantJA4 {
		t.Errorf("JA4 = %q, want %q", info.JA4, wantJA4)
	}
```

If they do **not** match, the local computation is wrong. Record both values, fix `ja.go` against the
reported values, and note in the spec which part disagreed. Do not freeze a value that was not
externally confirmed.

- [ ] **Step 6: Capture flow**

Enable capture. Set Windows or the browser's proxy to `127.0.0.1:8886`, browse to any HTTPS site, and
confirm:
- The card shows Listening, then a JA3 and JA4 with a timestamp.
- Browsing still works normally through the capture listener.
- A plain `http://` site also loads (Review Focus item 5, in the real world).

Switch the source to Captured, point the browser back at Caido's own port, and resend the Replay
request. `tls.ja4` must now match the captured JA4 rather than the preset's.

- [ ] **Step 7: WebSocket**

With routing on, open a WebSocket target (`wss://echo.websocket.org` or any in-scope target) through
Caido and confirm frames flow both ways and appear in Caido's WebSocket view.

- [ ] **Step 8: Failure behavior**

```bash
# From WSL, with mirrored networking:
tasklist.exe | grep -i awesome-tls-helper
taskkill.exe /F /IM awesome-tls-helper.exe
```

Confirm:
- A routed request fails rather than silently succeeding, and Caido's history shows the failure.
- The page reports Restarting, then Running again within about a second.
- After five rapid kills the page reports Failed with a Restart button, and Restart recovers it.

- [ ] **Step 9: Lifecycle**

Disable the plugin, then confirm no helper process remains:
```bash
tasklist.exe | grep -i awesome-tls-helper || echo "clean"
```
Re-enable it and confirm the settings, including the captured hello, survived.

- [ ] **Step 10: Confirm Replay and Automate coverage**

Send one request from Replay and one from Automate with routing on, and confirm both show the spoofed
fingerprint. If Automate bypasses `onUpstream`, record that in the spec as a limitation rather than
treating it as a defect — the probe in Task 1 already established which sources are covered.

- [ ] **Step 11: Write the README**

`README.md` must state: what it does; that it needs Caido >= 0.55 on Windows x64; how to build
(`pnpm install && pnpm build`); how to install the zip; that the routing rule is required for any
traffic to reach the plugin; the known limitations from spec section 12 (buffered responses, normalized
response header casing, malformed requests unsupported, Caido's upstream proxy not applied); and credits
for `bogdanfinn/tls-client` (BSD-4-clause, including its advertising clause), `bogdanfinn/utls`
(BSD-3-clause) and burp-awesome-tls (GPL-3.0) as the design inspiration.

- [ ] **Step 12: Record the results and commit**

Append a `### 11.3.1 Acceptance results (<date>)` subsection to the spec with the recorded fingerprint
values and anything that differed from the design.

```bash
pnpm test
git add README.md docs/ helper/internal/fingerprint/ja_test.go
git commit -m "test: confirm fingerprints end to end and freeze the JA3/JA4 vector"
```

---

## Appendix: Facts verified while writing this plan

Recorded so an implementer does not have to rediscover them, and so a wrong one is falsifiable.

| Fact | Where it was checked |
|---|---|
| `sdk.events.onUpstream` exists and returns `Connection \| RequestSpec \| {connection?,request?} \| undefined` | `@caido/sdk-backend@0.58.3/src/typing.d.ts` |
| Changing host/port on a returned `RequestSpec` does not reroute the connection | `doc-developer/src/plugins/guides/plugin_upstream.md` |
| `sdk.requests.send` inside `onUpstream` defaults to `plugins: false` | same guide |
| `Connection` exposes only `send(bytes)` and `receive(size?)` | `@caido/quickjs-types@0.26.0/src/caido/net.d.ts` |
| `ConnectionInfo` carries `host`, `port`, `tls`, `sni` | same file |
| Backend runtime has `child_process.spawn`, no `exec`, no stream `pipe` | `doc-developer/src/plugins/concepts/child_process.md` |
| `sdk.navigation.addPage(path, {body})`, `sdk.sidebar.registerItem(name, path, {icon})` | `@caido/sdk-frontend@0.58.3/src/types/sdks/{navigation,sidebar}.d.ts` |
| GraphQL has `plugins`, `upstreamPlugins`, `createUpstreamPlugin`, `updateUpstreamPlugin`; input is `{pluginId, allowlist, denylist, enabled}` | `@caido/sdk-frontend@0.58.3/src/types/__generated__/graphql-sdk.d.ts` |
| `profiles.DefaultClientProfile = Chrome_150`; `MappedTLSClients` holds ~80 profiles | `tls-client@v1.16.0/profiles/profiles.go` |
| `tls_client.NewHttpClient` with an explicit option list attaches no cookie jar; the convenience path does | `tls-client@v1.16.0/client.go:84-86`, `:276` |
| `fhttp` decompresses when the caller's `Accept-Encoding` mentions gzip, and unconditionally on HTTP/2 | `fhttp@v0.6.9/transport.go:2571`, `h2_bundle.go:9273` |
| `TransportOptions.DisableCompression` is the only way to stop that | `tls-client@v1.16.0/client_options.go:39` |
| `utls.Fingerprinter` has `RealPSKResumption`, removing the need to swap PSK extensions by hand | `utls@v1.7.8-barnius/u_fingerprinter.go:21` |
| `utls.ExtensionECH = 65037` and `utls.BoringGREASEECH()` are both exported | `utls@v1.7.8-barnius/common.go:137`, `u_ech.go:296` |
| This fork's `UClient` takes six arguments, not three | `utls@v1.7.8-barnius/u_conn.go:67` |
| `WithForceHttp1` rewrites ALPN only for named presets, not `HelloCustom` | `utls@v1.7.8-barnius/u_parrots.go:3264` |
| Scope-style patterns allow `a-z 0-9 . - _ * ?`; no paths or ports | `docs.caido.io/app/guides/scopes_defining` |
| Caido has no native fingerprint control | `github.com/caido/caido` issue 523, open |
