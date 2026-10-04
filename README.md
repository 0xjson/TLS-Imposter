# Awesome TLS for Caido

Makes Caido's outbound HTTPS requests carry a real browser's TLS (JA3/JA4) and
HTTP/2 fingerprint, so authorized security testing of WAF-protected targets
reflects how those targets behave for a browser.

Caido's own stack offers 31 ciphers and 11 extensions with **no ALPN**,
negotiates HTTP/1.1 and presents no HTTP/2 fingerprint at all — while sending a
Chrome `User-Agent`. That combination is self-contradictory and trivially
separable from a browser. Measured through Caido against `tls.peet.ws`:

| | Plugin off | Plugin on (`chrome_150`) |
|---|---|---|
| `http_version` | HTTP/1.1 | **h2** |
| `tls.ja3_hash` | `c199b43d41b470f8f68c5561f8f1ce3e` | `f984bd5bc7358922cde86ed4471a2e89` |
| `tls.ja4` | `t13d3111_e8f1e7e78f70_24695f2957a7` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `http2.akamai_fingerprint_hash` | *(absent)* | `52d84b11737d980aef856699f885ca86` |

HTTP/2 pseudo-header order reaches the wire as Chrome's, request header order is
preserved as written, and GREASE, X25519MLKEM768 and `application_settings`
(ALPS) all appear in the reported ClientHello.

## Requirements

- Caido **>= 0.55.0** (first version with `sdk.events.onUpstream`)
- Windows x64
- Go 1.26 and pnpm, to build from source

## Build and install

```bash
pnpm install
pnpm build          # cross-compiles the Go helper, then bundles the package
```

The result is `dist/plugin_package.zip`. In Caido: **Plugins → Install from
file**, then enable **both** components — the backend and the frontend. With the
backend disabled and the page enabled, every RPC answers 500; the page detects
that and says so rather than relaying a raw error.

### A routing rule is required

**Installing the plugin routes nothing.** Caido only hands a request to the
plugin when one of its own Upstream Plugins rules matches the target, so until a
rule exists no traffic reaches this plugin at all and the fingerprint is
unchanged.

The plugin page's **Enable for all domains** button creates that rule with
allowlist `*`. Finer-grained rules live in **Settings → Upstream → Upstream
Plugins**; the page reads whichever rule applies and reports it.

## Using it

### Everyday use

1. Open Caido with both plugin components enabled. The helper is spawned and
   supervised by the plugin — there is nothing to start by hand.
2. On the **Awesome TLS** page, check **Status**: the helper should read
   *Running*, and **Routing** should name your rule (`Routing *`). If routing
   reports no rule, click **Enable for all domains** — until a rule exists,
   nothing is routed and your fingerprint is unchanged.
3. In **Fingerprint**, leave the source on `preset` and pick a profile.
4. Use Caido normally. Proxy, Replay and Automate traffic to matching hosts all
   go out with that fingerprint.
5. To verify at any time, Replay `https://tls.peet.ws/api/all` and check
   `http_version` is `h2` and the JA3/JA4 match the profile.

### Capturing your own browser's ClientHello

The bundled presets drift from whatever browser you actually have installed — a
current Chrome may send an extra extension the preset does not, which changes
JA4. Capture makes the fingerprint exactly your browser's.

Turn **Capture** on, note the listen address, then launch a browser whose proxy
points at it (Windows `cmd`, not WSL — the path and `^` continuations are cmd
syntax):

```
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
  --proxy-server="http://127.0.0.1:8886" ^
  --user-data-dir="%TEMP%\awesome-tls-capture" ^
  --ignore-certificate-errors ^
  --no-first-run --no-default-browser-check ^
  --disable-background-networking --disable-sync --disable-component-update ^
  "https://tls.peet.ws/api/all"
```

Two flags are not optional:

- **`--user-data-dir`** must be a directory no running Chrome is using.
  Otherwise the new `chrome.exe` just hands the URL to the existing instance and
  silently discards every other flag, including the proxy — the usual reason
  capture appears to do nothing.
- **`--disable-background-networking`** (with `--disable-sync` and
  `--disable-component-update`) stops Chrome's own Google traffic. Because
  `--proxy-server` sends *all* of the browser's connections through the capture
  listener, and the most recent ClientHello wins, a background connection such
  as `mtalk.google.com` will otherwise overwrite the one you wanted — and that
  one carries no ALPN, so it cannot negotiate HTTP/2.

Then browse an HTTPS site, confirm the Capture card shows a new hello whose JA4
ends in `h2`, and switch the fingerprint source to `captured`. The hello is
stored, so the capture browser is only needed while capturing; turn Capture off
afterwards. Recapture after your browser updates.

### After reinstalling or upgrading the plugin

A reinstall gives the plugin a **new internal id**, which has two consequences:

- Its data directory is new, so settings return to defaults (`preset`,
  `chrome_150`, capture off) and any captured hello is gone.
- Upstream rules are keyed by plugin id, so re-check the **Routing** line and
  click **Enable for all domains** again if it reports no rule.

### When to turn routing off for a host

Per-host rules live in **Settings → Upstream → Upstream Plugins**. Turn routing
off for hosts where you send deliberately malformed requests (smuggling
payloads cannot survive the parse and rebuild), or where you need streaming —
responses are buffered, so SSE and long-polling do not stream and slow
responses hit the timeout.

### If something looks wrong

| Symptom | Cause |
|---|---|
| 502s on routed hosts | Helper is down. It fails closed rather than sending unspoofed — check Status and press Restart. |
| Fingerprint unchanged | No routing rule, or the rule is disabled. |
| Captured JA4 does not end in `h2` | The wrong connection was captured; see the flags above. |
| Page shows "Backend unavailable" | The backend component is disabled while the page is enabled. Enable both. |

## How it works

Caido's backend plugin runtime is QuickJS, which offers raw sockets but no
control over ClientHello construction or HTTP/2 framing — the entire point of
the plugin. So a Go helper, shipped as a backend asset and supervised by the
plugin, owns the outbound connection:

1. Caido matches its upstream rule and calls the plugin's `onUpstream` hook.
2. The plugin connects to the helper's loopback forward listener, writes a
   one-line preamble carrying that request's target, profile and timeout, and
   hands Caido the connection.
3. The helper re-sends the request through `tls-client` with the chosen browser
   profile and writes the response back down the same socket.

The helper is stateless with respect to settings — every connection carries its
own configuration — so restarting it loses nothing. It also holds anything
long-lived, because the backend SDK exposes no unload hook and a plugin
therefore cannot release what it opens.

**It fails closed.** If the helper is down, the request is answered with a 502
rather than sent with Caido's own fingerprint, so a dead helper cannot silently
leak an unspoofed request to the target.

## Known limitations

- Response header order and casing are normalized, because Go's response model
  does not preserve them. Same limitation as the Burp extension.
- Responses are buffered, so SSE and long-polling do not stream, slow responses
  hit the timeout, and large bodies occupy memory.
- Deliberately malformed requests (request-smuggling payloads, for example)
  cannot survive the parse and rebuild. Turn routing off for those hosts.
- Caido's own upstream proxy settings do not apply to routed traffic, since the
  helper opens the egress connection itself.
- Fingerprint mimicry is never perfect. Matching TLS and HTTP/2 while sending an
  inconsistent `User-Agent` or header set remains detectable; JA4 also encodes
  the ALPN result, so relayed HTTP/1.1 traffic differs from the `h2` a browser
  would show. This removes a decisive signal; it is not a bot-detection bypass.
- Windows x64 only in v1. Another platform is a `GOOS`/`GOARCH` change plus an
  extra asset.

## Credits

- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) — BSD-4-clause.
  Its advertising clause requires that all advertising materials mentioning
  features or use of this software display the acknowledgement: *"This product
  includes software developed by the copyright holders."*
- [bogdanfinn/utls](https://github.com/bogdanfinn/utls), a fork of
  [refraction-networking/utls](https://github.com/refraction-networking/utls) —
  BSD-3-clause
- [sleeyax/burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls) —
  GPL-3.0, the design inspiration for this plugin. No code was copied from it;
  the approach of retargeting proxy requests at a local Go server that owns the
  TLS handshake is taken from its design.

Design, probe results and acceptance measurements are written up in
`docs/superpowers/specs/2026-10-03-caido-awesome-tls-design.md`.
