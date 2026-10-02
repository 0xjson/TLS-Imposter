# Caido Awesome TLS — Design

- **Date:** 2026-10-03
- **Status:** Draft, awaiting review
- **Prior art:** [sleeyax/burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls) (Burp Suite extension, GPL-3.0)

## 1. Purpose

Caido's own HTTP stack has a distinctive TLS and HTTP/2 fingerprint. Security testing traffic sent
through Caido is therefore easy for WAF and bot-management products to separate from browser traffic,
which blocks legitimate authorized testing of the sites that use them.

This plugin makes Caido's outbound HTTPS requests present the TLS fingerprint (JA3/JA4) and HTTP/2
fingerprint of a real browser, so that testing a target reflects how the target behaves for a browser.
It is the Caido equivalent of Awesome TLS for Burp.

- **Audience:** personal use. Installed from a local zip. Not published, not submitted to the Caido store.
- **Platform:** Caido desktop app on Windows x64, Caido **>= 0.55.0** (first version with
  `sdk.events.onUpstream`). Development happens in WSL2, which uses mirrored networking, so `127.0.0.1`
  is shared with the Windows host.

### Success criteria

1. With routing on, a Replay request to `https://tls.peet.ws/api/all` reports the JA3/JA4 and Akamai
   HTTP/2 fingerprint of the selected browser profile, and both differ from Caido's native fingerprint
   observed with the plugin off.
2. The header order the endpoint reports matches the request as written in Replay.
3. With capture on and the browser pointed at the capture port, the captured hashes appear in the plugin
   UI; with source `captured`, the endpoint reports the browser's own JA3/JA4.
4. WebSocket connections still work on routed domains.
5. Proxy, Replay and Automate traffic are all covered.

## 2. Scope

**In scope (v1)**

- Preset browser profiles from `bogdanfinn/tls-client`: ClientHello plus HTTP/2 SETTINGS, window update,
  priority frames and pseudo-header order.
- Request header order, casing and duplicates preserved end to end.
- Configurable timeout.
- Plugin page in Caido's sidebar: status, settings, and one-click creation of the Caido upstream-plugin
  routing rule.
- Capture of the local browser's real ClientHello through a pass-through listener, reusable as the
  fingerprint source.
- `Upgrade` / WebSocket requests relayed as bytes under the spoofed ClientHello.

**Out of scope (v1)**

- UI field for pasting a custom hex ClientHello. The parsing code exists internally for capture; only the
  input field is omitted.
- Chaining the helper's egress through another proxy.
- Platforms other than Windows x64. Adding one is a `GOOS`/`GOARCH` change plus an extra asset.
- Caido store submission, telemetry, self-update.
- HTTP/3, per-domain profile selection, streaming responses, byte-exact forwarding of malformed requests.

## 3. Background

### 3.1 How the Burp extension works

A Burp proxy request handler retargets each request at a local HTTPS server (Go, loaded over JNA) and
attaches a magic `Awesometlsconfig` header carrying JSON: real host and scheme, fingerprint, header
order, timeout. The Go server strips that header and re-sends the request with `tls-client`, building a
fresh client per request. An optional listener placed between the browser and Burp sniffs the browser's
ClientHello for reuse as the fingerprint.

### 3.2 Caido facts this design depends on

- Caido has no native fingerprint control. [caido/caido#523](https://github.com/caido/caido/issues/523)
  is open and backlogged.
- `sdk.events.onUpstream(cb)` (backend SDK, Caido >= 0.55) calls
  `cb(sdk, request: RequestSpecRaw)` and accepts
  `Connection | RequestSpec | { connection?, request? } | undefined`.
  - It fires only for domains the user enabled for this plugin under Caido's **Upstream Plugins**
    settings. Those rules carry an allowlist, denylist, enabled flag and rank, and are also reachable
    over GraphQL (`upstreamPlugins`, `createUpstreamPlugin`, `updateUpstreamPlugin`,
    `toggleUpstreamPlugin`).
  - It runs on the request hot path and is documented as synchronous, so it must stay cheap.
  - Changing host or port on a returned `RequestSpec` does **not** change where Caido connects. Only a
    returned `Connection` does, obtained from `sdk.net.connect(ConnectionInfo | url)`.
  - `Connection` exposes `send(bytes)` and `receive(size)`, so the plugin can write a preamble before
    handing the connection to Caido.
  - `sdk.requests.send()` called inside `onUpstream` defaults to `plugins: false`, which prevents
    recursion.
- The backend runtime is QuickJS/LLRT, offering `child_process.spawn` (no `exec`, no stream `pipe`),
  `fs` and `fs/promises` (including `chmod`), `path`, `os`, `net`, and partial `crypto`.
- Backend assets declared in `caido.config.ts` are readable at runtime under `sdk.meta.assetsPath()`.
  `sdk.meta.path()` is a writable per-plugin data directory.
- Scope-style patterns (used by upstream rules) allow `a-z`, `0-9`, `.`, `-`, `_`, `*`, `?`, where `*`
  matches many characters and `?` matches one. No paths, no ports.

### 3.3 Why a Go helper rather than pure TypeScript

The backend runtime offers `net` sockets but no control over TLS ClientHello construction or HTTP/2
frame settings, which is the entire point of the plugin. `tls-client` and `utls` provide that control,
are already proven by the Burp extension, and ship roughly 80 maintained profiles (current Chrome,
Firefox, Safari/iOS, Brave, Opera, plus mobile app profiles). `tls-client` is BSD-4-clause; `utls` is
BSD-3-clause.

Caido's own [tls-impersonate](https://github.com/caido/tls-impersonate) was considered and rejected: it
is a small Rust OpenSSL library, is not wired into Caido, does not implement extension ordering, and
would mean writing the HTTP layer from scratch.

## 4. Architecture

```
Browser --> Caido proxy --> onUpstream (backend plugin)
                                 | sdk.net.connect("127.0.0.1:<helper port>")   plain TCP
                                 | send "AWESOMETLS/1 {token,target,profile,...}\n"
                                 | return { connection }
                                 v
                     awesome-tls-helper.exe   (Go, spawned by the plugin)
                                 | parse the HTTP/1.1 request Caido writes
                                 | re-send it with tls-client (browser TLS + HTTP/2)
                                 v
                              Target  --> buffered response as HTTP/1.1 --> Caido

Optional capture path:
Browser --> helper capture listener :8886 --(byte pipe, sniff ClientHello)--> Caido proxy :8080
```

The request Caido recorded is never rewritten, so Caido's history shows exactly what was sent. There is
no magic header: the target and settings travel out-of-band in the connection preamble.

### 4.1 Components

| Component | Responsibility |
|---|---|
| **Backend plugin** (TypeScript, QuickJS) | Owns and persists settings; spawns and supervises the helper; registers `onUpstream`; exposes an RPC API and pushes state events to the frontend. |
| **Go helper** (`awesome-tls-helper.exe`) | Forward listener on a random loopback port: parses requests, re-sends through `tls-client`, writes buffered HTTP/1.1 responses; relays `Upgrade` connections; optional capture listener; computes JA3/JA4. Stateless with respect to settings — everything arrives per connection or per control message. |
| **Frontend page** (Vue 3 + PrimeVue, Caido sidebar) | Status card, fingerprint card, capture card, routing-rule shortcut. |

### 4.2 Repository layout

```
caido-awesome-tls/
  caido.config.ts              # id "awesome-tls", name "Awesome TLS"; backend assets include bin/
  package.json, pnpm-workspace.yaml
  packages/
    backend/
      src/
        index.ts               # init(): settings, helper manager, upstream hook, RPC
        settings.ts            # schema, defaults, validation, load/save settings.json
        helper.ts              # spawn + supervise, stdout protocol, restart backoff
        preamble.ts            # build the per-connection preamble line
        upstream.ts            # the onUpstream handler
      assets/bin/              # build output: awesome-tls-helper.exe (generated, not edited)
    frontend/
      src/                     # page registration, App.vue, cards, routing-rule helper
  helper/                      # Go module
    cmd/awesome-tls-helper/main.go
    internal/
      control/                 # stdin/stdout JSON-lines protocol
      preamble/                # parse + validate the preamble line
      httpwire/                # raw HTTP/1.1 request parsing, response writing
      forward/                 # tls-client client cache + forwarding
      relay/                   # Upgrade/WebSocket byte relay over uTLS
      capture/                 # capture listener + ClientHello sniffer
      fingerprint/             # raw ClientHello -> uTLS spec, JA3, JA4, profile lookup
  docs/superpowers/specs/
```

### 4.3 Trust boundary

The helper's forward listener is a local HTTP-forwarding service, so it must not become an open proxy
for other software on the machine.

- It binds `127.0.0.1` on port `0` (kernel-assigned) and reports the port over stdout.
- At startup it generates a 32-byte random token, emits it on stdout, and requires it in every preamble.
  Comparison is constant-time. The token never appears in log output.
- The capture listener also binds loopback only.

## 5. Protocols

### 5.1 Control channel (plugin <-> helper, stdin/stdout, one JSON object per line)

Helper to plugin, on stdout:

| `type` | Fields | When |
|---|---|---|
| `ready` | `port`, `token`, `profiles[]`, `defaultProfile`, `version` | Once, after the forward listener is bound |
| `capture-status` | `state` (`listening` \| `stopped` \| `error`), `listen`, `error?` | After each `capture` command, or if the listener dies |
| `captured` | `clientHello` (hex), `ja3`, `ja3Text`, `ja4`, `capturedAt` (ISO 8601) | A ClientHello was captured and converted successfully |
| `capture-rejected` | `error`, `ja4?` | A captured ClientHello could not be converted to a uTLS spec |
| `log` | `level`, `msg` | Diagnostics. Never includes the token. |

Plugin to helper, on stdin:

| `type` | Fields |
|---|---|
| `capture` | `enabled`, `listen` (`host:port`), `forwardTo` (`host:port`) |

**EOF on stdin means shut down**, so the helper cannot outlive the plugin. Human-readable diagnostics go
to stderr and are surfaced in Caido's backend log.

### 5.2 Connection preamble (plugin to helper, first bytes of every forward connection)

```
AWESOMETLS/1 {"token":"...","target":{"host":"example.com","port":443,"tls":true},"sni":null,"profile":"chrome_150","clientHello":null,"timeoutSec":30}\n
```

- `token` — from `ready`; mismatch closes the connection.
- `target` — from `request.getInfo()`. This is what the helper dials, independent of the `Host` header.
- `sni` — SNI override from `getInfo().sni`, else `null`, in which case the default is the target host
  (and omitted for IP literals).
- `profile` — a `tls-client` profile name. When `clientHello` is set, the profile contributes only the
  HTTP/2 layer.
- `clientHello` — captured ClientHello hex when the source is `captured`, else `null`.
- `timeoutSec` — whole-request deadline.

The preamble line is capped at 64 KiB; anything longer or malformed closes the connection with a log
line. Every request Caido writes on that connection (keep-alive) uses this target and configuration.

## 6. Request forwarding

### 6.1 Parsing what Caido writes

- Request line: `METHOD SP request-target SP HTTP/1.x`. The request-target is preserved verbatim via
  `URL.Opaque` so it is never re-encoded. Absolute-form targets are reduced to origin-form.
- Headers are kept as an ordered list of `(name, value)` pairs, preserving casing and duplicates.
- Body: `Transfer-Encoding: chunked` is decoded; otherwise `Content-Length` bytes are read; otherwise
  there is no body. Request bodies are capped at 256 MiB.
- A request carrying `Upgrade` with `upgrade` in `Connection` is handed to the relay (section 7).

### 6.2 Building the outgoing request

- URL is `https://host[:port]` (or `http://`) from the preamble target, with the parsed request-target.
- Header order is passed to `tls-client` through `fhttp.HeaderOrderKey`, lowercased, as the library
  requires.
- `Content-Length` is removed before sending; the library sets it from the actual body.
- For HTTP/2, header names are lowercased and connection-specific headers that are illegal in HTTP/2
  (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`) are dropped. The
  profile supplies pseudo-header order.
- Client options, fixed: no redirect following, no certificate verification (this is a testing proxy
  where the operator inspects traffic), **no cookie jar** (`tls-client`'s convenience constructor adds
  one; the explicit option list does not), and `TransportOptions{DisableCompression: true}`.
- `timeoutSec` from the preamble is applied as the library's timeout.

`DisableCompression` deserves a note, because the obvious choice is wrong. `fhttp` departs from the Go
standard library here: on HTTP/1.1 it decompresses whenever the *caller's* `Accept-Encoding` mentions
gzip (`transport.go:2571`), not only when the transport added the header itself, and on HTTP/2 it
decompresses unconditionally (`h2_bundle.go:9273`). Left at the default, the helper would hand Caido a
decompressed body still labelled `Content-Encoding: gzip` — which is exactly what the Burp extension
does, patching `Content-Length` to match and leaving the encoding header contradicting the bytes.
Setting `DisableCompression: true` keeps the body as the server sent it, so `Content-Encoding`,
`Content-Length` and the bytes agree and Caido can decode the response itself.

### 6.3 Client cache

One `tls_client.HttpClient` per cache key `(profile, clientHelloHash, timeoutSec)`, held in a map with a
mutex and an idle eviction after 10 minutes. This keeps connection pooling and session resumption per
profile, which is how a browser behaves. The Burp extension builds a client per request, forcing a fresh
handshake every time — itself an anomalous pattern.

### 6.4 Writing the response back

Per the review decision, responses are **buffered**, matching the Burp extension:

1. Read the full body, still compressed.
2. Emit `HTTP/1.1 <code> <reason>`, then the response headers, with `Content-Length` set to the exact
   byte length and any `Transfer-Encoding` removed.
3. Write the body.

The connection stays open for keep-alive, so the next request reuses the preamble.

Consequences, recorded as limitations in section 12: no streaming for SSE or long-polling; a response
slower than the timeout surfaces as `504`; large downloads are held in memory first.

## 7. Upgrade / WebSocket relay

Browsers use HTTP/1.1 for WebSockets, so the relay path mirrors that:

1. Dial the target and complete the uTLS handshake with the same ClientHello, offering only `http/1.1`
   in ALPN.
2. Write the original request bytes unchanged.
3. Copy bytes in both directions until either side closes.

This preserves exact framing for WebSocket traffic, which the rebuild path in section 6 could not.

## 8. Capture flow

1. The user enables capture and points the browser at the capture listener (default `127.0.0.1:8886`)
   instead of Caido. The helper connects onward to Caido (default `127.0.0.1:8080`) and relays bytes
   untouched in both directions.
2. On the browser-to-Caido side, after the `CONNECT` line, the sniffer locates the first TLS handshake
   record and reads the complete ClientHello using `io.ReadFull`. The Burp implementation uses bare
   `Read` calls, which can truncate a ClientHello on a partial read; this design avoids that.
3. The helper converts the bytes to a uTLS spec, computes JA3 and JA4, and emits `captured`. The plugin
   stores the most recent one in `settings.json`, so it survives restarts, and shows its timestamp and
   hashes.
4. With source `captured`, the TLS ClientHello comes from the browser while the HTTP/2 layer comes from
   the selected preset. The UI advises choosing a preset from the same browser family.
5. Fix-ups carried over from the Burp extension, applied at conversion time:
   - An Encrypted ClientHello extension is replaced with a GREASE ECH placeholder, since real ECH is not
     supported.
   - A captured PSK extension (session resumption) arrives as a "fake" extension and is replaced with a
     working one.
6. Conversion failures emit `capture-rejected`; the previous good capture is kept and the UI shows a
   warning.

Capture is throttled: at most one `captured` event per 2 seconds, and identical hellos are not re-sent.

## 9. Settings and UI

Settings live in `settings.json` under `sdk.meta.path()`, owned by the backend, and apply immediately
with no restart.

| Setting | Default |
|---|---|
| `source` | `preset` (alternative: `captured`) |
| `profile` | the newest Chrome profile the helper reports (`chrome_150` in the pinned library version) |
| `timeoutSec` | 30 |
| `capture.enabled` | false |
| `capture.listen` | `127.0.0.1:8886` |
| `capture.forwardTo` | `127.0.0.1:8080` |
| `capture.last` | `null`, else `{clientHello, ja3, ja4, capturedAt}` |

Validation: `profile` must be in the helper's list, `timeoutSec` in 1..600, addresses must be
`host:port` with a loopback host. Invalid values fall back to defaults with a log line.

The page has three cards:

- **Status** — helper state (`running` / `restarting` / `failed`, with last error and a Restart button);
  routing state, with an "Enable for all domains" button that creates the upstream-plugin rule with
  allowlist `*`; a note that Caido's own upstream proxy setting does not apply to routed traffic.
- **Fingerprint** — source toggle, searchable profile dropdown, timeout.
- **Capture** — enable toggle, both addresses, the instruction to point the browser at the listen
  address, and the last capture with its hashes and a Clear button.

Routing rules beyond the `*` shortcut are managed in Caido's own Upstream Plugins settings; the page
links there rather than reimplementing rule editing.

## 10. Lifecycle and failure behavior

**Startup.** `init()` loads settings, then spawns `assetsPath()/bin/awesome-tls-helper.exe` with
`stdio: ["pipe","pipe","pipe"]`, and waits up to 10 s for `ready`. On `ready` it records port, token and
profile list, then sends the `capture` command if capture is enabled. The hook is registered immediately
so Caido never sees a missing handler.

**Crash recovery.** Exit before an intentional shutdown triggers a restart with backoff
1 s, 2 s, 4 s, 8 s, 16 s, capped at 30 s. Five failures inside 60 s moves the state to `failed`, which
stops automatic retries, records the last stderr output, and waits for a manual Restart.

**Shutdown.** Plugin unload or disable closes the helper's stdin, which makes it exit. The plugin also
kills the process if it has not exited within 2 s.

**No console window.** The helper is linked with `-H windowsgui` so launching it does not flash a
console window on Windows. Its stdio pipes still work because the plugin creates them.

**The fallback responder.** `init` starts a `net` listener on `127.0.0.1:0` that writes a fixed
`502` response to any connection and closes it. It exists for the whole plugin lifetime, costs one
socket, and is the only way to deny a request on a platform that fails open. Task 1 verified that
Caido relays a response from a plugin-owned listener verbatim, so the operator sees the 502 in
Caido's history rather than a silent success.

**The fallback responder.** `init` starts a `net` listener on `127.0.0.1:0` that writes a fixed
`502` response to any connection and closes it. It lives for the whole plugin lifetime, costs one
socket, and is the only way to deny a request on a platform that fails open. Task 1 verified that
Caido relays a response from a plugin-owned listener verbatim, so the operator sees the 502 in
Caido's history rather than a silent success with the wrong fingerprint.

**Failure modes:**

| Condition | Behavior |
|---|---|
| Helper not running | `onUpstream` returns a connection to the plugin's own fallback responder, which replies `502` with `X-Awesome-Tls-Error: helper unavailable`. The request never leaves the machine. Throwing would **not** work: Task 1 showed Caido then sends the request itself with its own fingerprint (spec 11.1.1, Q4). The status card explains the cause. |
| DNS, connection refused, TLS handshake error | `502` with `X-Awesome-TLS-Error` and the reason in the body, visible in Caido's history. |
| Timeout | `504`, same shape. |
| Bad token or malformed preamble | Connection closed, event logged. |
| Unusable captured hello | Rejected at capture time, warning in the UI, previous capture retained. |

## 11. Testing

### 11.1 Step 0: throwaway probe of Caido's behavior

Before building anything real, a minimal plugin that logs and echoes confirms the assumptions this design
rests on. Findings are recorded in this spec; the probe code is thrown away.

1. Does Caido write plain HTTP/1.1 into a plugin-supplied connection, including for HTTPS targets and for
   browser requests that arrived over HTTP/2?
2. Does a preamble written before returning the connection arrive ahead of the request?
3. Does Caido reuse the connection for keep-alive, and if so, does it keep the same target?
4. What happens when the hook throws — does the request fail, or does Caido fall back to sending it
   itself? **If it falls back, fail-closed is not achievable and that part of the design is revisited
   with the user before implementation continues.**
5. Do WebSocket upgrades reach `onUpstream`?
6. Do Proxy, Replay and Automate traffic all trigger it?
7. Does the helper exit when the plugin is disabled, and do stdio pipes work in a `-H windowsgui` build?
8. Does rule pattern `*` match every domain?

### 11.2 Automated tests

Go helper (`go test`, runs in WSL; the logic is OS-independent):

- Unit: request parsing (order, casing, duplicates, chunked bodies, verbatim targets); response writing
  (`Content-Length` recomputed, `Transfer-Encoding` dropped); preamble and token validation; ClientHello
  capture against recorded Chrome and Firefox hellos, including deliberately fragmented reads; the ECH
  and PSK fix-ups; client cache keying and eviction.
- Integration, against local test servers with no internet dependency: the helper's own ClientHello
  yields the JA3/JA4 expected for the profile; HTTP/2 SETTINGS and pseudo-header order match the
  profile; header order survives; keep-alive works; the WebSocket relay round-trips; `502`/`504` paths;
  token rejection; capture end to end through a loopback pair.

Backend TypeScript (vitest, SDK stubbed): preamble construction, settings defaults and validation,
parsing helper stdout, restart backoff state machine.

Frontend: type check, then manual inspection.

### 11.3 End-to-end acceptance

Run against Caido on Windows. The user starts Caido and installs the zip; the rest is driven from WSL via
the Caido MCP tools and curl.

1. Replay to `https://tls.peet.ws/api/all` reports the selected profile's JA3/JA4 and HTTP/2 fingerprint,
   compared against a plugin-off baseline. Reported header order matches the request.
2. Capture: browser through `:8886`, hashes appear; with source `captured`, the endpoint reports the
   browser's fingerprint.
3. A WebSocket echo works with routing on.
4. Killing the helper makes routed requests fail with a clear error; it then restarts automatically.
5. Disabling the plugin leaves no helper process behind.

## 12. Known limitations

- Response header order and casing are normalized, because Go's response model does not preserve them.
  Same limitation as the Burp extension.
- Responses are buffered, so SSE and long-polling do not stream, slow responses hit the timeout, and
  large bodies occupy memory.
- Deliberately malformed requests (for example request-smuggling payloads) cannot survive the parse and
  rebuild. Turn routing off for those hosts.
- Caido's own upstream proxy settings do not apply to routed traffic, since the helper opens the egress
  connection.
- Fingerprint mimicry is never perfect. Matching TLS and HTTP/2 while sending an inconsistent
  `User-Agent` or header set remains detectable; JA4 also encodes the ALPN result, so relayed
  HTTP/1.1 traffic differs from the `h2` a browser would show.
- Windows x64 only in v1.

## 13. Licensing and credits

Personal use, not distributed. The README credits `bogdanfinn/tls-client` (BSD-4-clause),
`refraction-networking/utls` via `bogdanfinn/utls` (BSD-3-clause), and burp-awesome-tls (GPL-3.0) as the
design inspiration. The BSD-4-clause advertising clause is noted in the README. If any Burp extension
code is copied rather than reimplemented from its ideas, the project is licensed GPL-3.0.

## 14. Open questions

Nothing is blocked on the user. Two items are settled by the section 11.1 probe before implementation
proceeds, and only one can change the design:

- **Probe item 4, hook-throw behavior.** If Caido falls back to sending the request itself when the hook
  throws, fail-closed is unachievable and section 10 is revisited with the user before any further work.
- **Probe items 1-3 and 5-8** adjust implementation details (framing, keep-alive handling, which traffic
  sources are covered) but not the architecture.

### 11.1.1 Probe results (2026-10-03)

Run against Caido **0.58.3** on Windows x64, rule `allowlist: ["*"]`, throwaway probe
plugin. Evidence in `AppData/Roaming/Caido/Caido/data/logs/logging.2026-10-02.log`.

| # | Question | Answer |
|---|---|---|
| 1 | Plain HTTP/1.1 into a plugin-supplied connection, incl. HTTPS targets? | **Yes.** Byte-exact HTTP/1.1, header order, casing and duplicates preserved, for a `tls=true`/`port=443` target. |
| 2 | Does a preamble written before returning arrive first? | **Yes.** Logged as two distinct reads: 42 B preamble, then the request bytes. |
| 3 | Does Caido reuse the connection (keep-alive)? | **No.** Each request gets a fresh `onUpstream` call and a fresh connection; the previous one closes after exactly one request. |
| 4 | What happens when the callback throws? | **Caido FAILS OPEN.** A deliberate `throw` is logged as "Error in plugin execution" and Caido then sends the request itself. Confirmed 4x (3 accidental runtime errors + 1 deliberate throw) across Replay and Proxy, each returning the real upstream response. |
| 5 | Do WebSocket upgrades reach `onUpstream`? | **Yes.** `Upgrade: websocket`, `Connection: Upgrade` and `Sec-WebSocket-Key` all arrive intact. |
| 6 | Proxy, Replay, Automate? | **Proxy yes, Replay yes.** Automate not exercised; it shares the Replay request engine. Confirm in Task 19 Step 10. |
| 7 | Helper exits when the plugin is disabled? | Deferred to Task 12 (no helper yet). `togglePlugin` does tear down and re-create the backend runtime, so an `init`-owned child process gets a real shutdown signal. |
| 8 | Does `*` match every domain? | **Yes.** `allowlist: ["*"]` alone routed `example.com` and `ws.postman-echo.com`. |

#### Runtime facts that contradict the SDK types

Three findings that change the implementation, each verified in the live runtime:

1. **`TextDecoder` / `TextEncoder` do not exist.** `TextDecoder is not defined` at
   runtime; neither appears anywhere in `@caido/quickjs-types@0.26.0`. Use
   `Buffer.from(bytes).toString("latin1")` to decode, and pass a plain string to
   `Connection.send`, which is legal because
   `Bytes = string | Array<number> | Uint8Array` (`caido/shared.d.ts:16`).
2. **`ConnectionInfo` exposes `isTLS` and `SNI`, not `tls` and `sni`.** The `.d.ts`
   declares `get tls(): boolean` and `get sni(): string | undefined`, but the live
   object's prototype is `["toString", "isTLS", "host", "port", "SNI"]`, and
   `info.tls` / `info.sni` are `undefined`. Reading `info.tls` would have sent every
   HTTPS request as plaintext, and TypeScript would not have caught it.
3. **`Buffer.indexOf("\r\n\r\n")` does not match** in this runtime. Accumulate
   `latin1` strings and use `String.indexOf` for byte-exact scanning.

Also corrected: the root GraphQL field is **`pluginPackages`**, not `plugins`
("Unknown field \"plugins\" on type \"QueryRoot\""). `updateUpstreamPlugin(id:, input:)`
and `toggleUpstreamPlugin(id:, enabled:)` match the design. `togglePlugin(id:, enabled:)`
exists and reloads a backend plugin's code; switching projects does **not**.

### 11.3.1 Helper-level fingerprint confirmation (2026-10-03, Task 12)

Before the plugin existed, the shipped Windows cross-compile was driven directly
over its control protocol from WSL and pointed at `https://tls.peet.ws/api/all`.
This confirms the core mechanism independently of Caido.

| | `chrome_150` | `firefox_148` |
|---|---|---|
| `http_version` | **h2** | **h2** |
| `tls.ja3_hash` | `f984bd5bc7358922cde86ed4471a2e89` | `992b82b242c18c86da84eff5bf3e3100` |
| `tls.ja4` | `t13d1516h2_8daaf6152771_806a8c22fdea` | `t13d1917h2_4d8ed5baf28e_3cbfd9057e0d` |
| `tls.peetprint_hash` | `67c3e9111bed9e7f03d2f21d6d88994b` | `ec345e44ccb04da8547a9f2542be9f0d` |
| `http2.akamai_fingerprint_hash` | `52d84b11737d980aef856699f885ca86` | `6ea73faa8fc5aac76bded7bd238f6433` |

Three things this establishes:

1. **HTTP/2 is negotiated and fingerprinted.** `http_version: h2` plus a distinct
   `akamai_fingerprint_hash` per profile means the HTTP/2 layer is being set, not
   just the TLS layer. That half is what a TLS-only byte pipe could not have given.
2. **Profile selection takes effect.** Every reported value differs between the two
   profiles.
3. **This repo's JA3 and JA4 implementations are externally correct.** The values
   computed locally from `testdata/chrome.hello` match what tls.peet.ws reported
   byte for byte, so `TestAnalyzeAcceptsTheRecordedChromeHello` now asserts them as
   a frozen vector. Task 19 Step 5 is satisfied early; it remains only to confirm
   the same values once the traffic flows through Caido rather than straight from
   the helper.

Also settled here: probe question 7. The `-H windowsgui` binary
(`PE32+ ... (GUI), x86-64`, 11.4 MB) receives its `ready` line over a pipe in
0.23 s and exits with code 0 when stdin closes, so the GUI subsystem does not
break stdio and the helper cannot outlive the plugin.

### 11.3.2 Acceptance through Caido (2026-10-03, Task 19)

Plugin installed in Caido 0.58.3 on Windows, upstream rule `allowlist: ["*"]`,
request to `https://tls.peet.ws/api/all` through Caido's proxy.

| | Plugin off (Caido's own stack) | Plugin on |
|---|---|---|
| `http_version` | **HTTP/1.1** | **h2** |
| `tls.ja3_hash` | `c199b43d41b470f8f68c5561f8f1ce3e` | `f984bd5bc7358922cde86ed4471a2e89` |
| `tls.ja4` | `t13d3111_e8f1e7e78f70_24695f2957a7` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `tls.peetprint_hash` | `5d70f9266079843b0c0824fd3005e65d` | `67c3e9111bed9e7f03d2f21d6d88994b` |
| `http2.akamai_fingerprint_hash` | *(absent — no HTTP/2)* | `52d84b11737d980aef856699f885ca86` |

The plugin-on values are **identical** to those measured by driving the helper
directly (11.3.1), so routing through Caido does not perturb the fingerprint.

Why the baseline is bad for its stated purpose: Caido natively offers 31 ciphers
and 11 extensions with **no ALPN**, negotiates HTTP/1.1, and presents no HTTP/2
fingerprint at all — while sending a Chrome `User-Agent`. That combination is
self-contradictory and trivially separable from a browser.

Confirmed alongside it:

- **HTTP/2 pseudo-header order** reaches the wire as `:method, :authority,
  :scheme, :path` — Chrome's order; Firefox's differs — so the profile's HTTP/2
  layer is applied, not just its ClientHello.
- **Request header order** is preserved: `user-agent, accept, accept-language,
  accept-encoding`, exactly as written.
- **GREASE, X25519MLKEM768 key share and `application_settings` (ALPS)** all
  appear in the reported ClientHello, as current Chrome sends.

#### Fail-closed, and what it cost to learn

With the helper killed and its binary moved aside so it could not respawn, the
plugin logged `helper down; answering 502` and **the request never reached the
target** — Caido returned its own error page, not the site's response. The
security property holds.

Getting there exposed four defects that every unit test had passed:

1. **Boot order.** `helper.start()` ran after a settings load and two GraphQL
   calls, unguarded. `sdk.graphql.execute` rejects an `undefined` variables
   argument ("GraphQL variables must be an object"), so the helper never
   started and nothing was logged — the UI would have shown "stopped" forever.
   Boot now runs in guarded phases, helper first.
2. **Answer-before-read.** Caido writes the request into the supplied
   connection and then reads; answering first makes it discard the reply.
3. **Self-close aborts.** Ending the socket produces `os error 10053` and Caido
   serves its own 400 instead of relaying the 502. The responder now writes a
   keep-alive response and lets the peer close — the shape the Task 1 probe
   used, which Caido relayed correctly.
4. **No unload hook.** The backend SDK's only events are `onInterceptRequest`,
   `onInterceptResponse`, `onProjectChange` and `onUpstream`; there is no
   unload or shutdown callback. A listener created in `init` can therefore
   never be deliberately released. The long-lived 502 listener leaked and
   **Caido's backend process died while stopping the plugin**. The responder is
   now opened per denied request and closes itself after one connection, so a
   healthy helper leaves no extra socket open at all.

Item 4 is the general lesson for this plugin: anything it opens must be either
short-lived or owned by the helper process, because the plugin gets no chance
to clean up.
