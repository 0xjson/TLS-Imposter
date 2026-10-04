# TLS Imposter

A Caido plugin that gives Caido's outbound HTTPS connections the TLS and HTTP/2
fingerprint of a real browser.

## The problem it solves

Caido's own TLS stack is distinctive. It offers 31 ciphers and 11 extensions,
sends **no ALPN**, and therefore negotiates HTTP/1.1 and presents no HTTP/2
fingerprint at all — while your requests carry a Chrome `User-Agent`.

That combination is self-contradictory. Any WAF or bot-management product can
separate it from browser traffic on the handshake alone, before looking at a
single byte of your request. Authorized testing of a protected target then
measures the WAF's opinion of your tooling rather than the target's behaviour.

TLS Imposter removes that signal. Measured through Caido against
`tls.peet.ws/api/all`:

| | Plugin off | Plugin on (`chrome_150`) |
|---|---|---|
| `http_version` | HTTP/1.1 | **h2** |
| `tls.ja3_hash` | `c199b43d41b470f8f68c5561f8f1ce3e` | `f984bd5bc7358922cde86ed4471a2e89` |
| `tls.ja4` | `t13d3111_e8f1e7e78f70_24695f2957a7` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `http2.akamai_fingerprint_hash` | *(absent)* | `52d84b11737d980aef856699f885ca86` |

The HTTP/2 pseudo-header order arrives as Chrome's (`m,a,s,p`), your request
header order is preserved exactly as written, and GREASE, X25519MLKEM768 and
`application_settings` (ALPS) all appear in the handshake as current Chrome
sends them.

## What it is not

- **Not a bot-detection bypass.** It removes one decisive signal. IP reputation,
  JS challenges, client hints and behaviour over time are untouched, and a
  fingerprint that disagrees with your `User-Agent` is still detectable.
- **Not a proxy replacement.** Caido stays in the path and still records
  everything. This changes only how Caido's own egress connection is made.
- **Not transparent to malformed traffic.** Requests are parsed and rebuilt, so
  smuggling payloads do not survive. See [Limitations](#limitations).

## Requirements

- Caido **>= 0.55.0** — the first release with `sdk.events.onUpstream`
- Windows x64
- To build: Go 1.26 and pnpm

## Install

```bash
pnpm install
pnpm build        # cross-compiles the Go helper, then bundles the package
```

Install the resulting `dist/plugin_package.zip` through **Plugins → Install from
file**, and enable **both** components — backend and frontend. With the backend
disabled while the page is enabled, every call answers 500; the page detects
that and explains it rather than surfacing a raw error.

### Then add a routing rule, or nothing happens

Caido hands a request to a plugin only when one of its **Upstream Plugins**
rules matches the target. Until such a rule exists, no traffic reaches TLS
Imposter and your fingerprint is unchanged — installing the plugin is not
enough.

The plugin page's **Enable for all domains** button creates the rule with
allowlist `*`. Per-host rules live in **Settings → Upstream → Upstream
Plugins**, and the page reports whichever rule applies.

## Daily use

1. Open Caido with both components enabled. The helper process is spawned and
   supervised by the plugin; there is nothing to start by hand.
2. On the **TLS Imposter** page, confirm **Helper: Running** and that
   **Routing** names your rule.
3. Pick a profile in the Fingerprint card. Roughly 80 are available — current
   Chrome, Firefox, Safari/iOS, Brave, Opera, and mobile app profiles.
4. Use Caido normally. Proxy, Replay and Automate traffic to matching hosts all
   leave with that fingerprint.

To check at any time, Replay `https://tls.peet.ws/api/all` and confirm
`http_version` is `h2`.

### Turning routing off for a host

Do it for hosts where you send deliberately malformed requests, and for
endpoints you need to stream — responses are buffered, so SSE and long-polling
will not work and slow responses hit the timeout.

### After reinstalling the plugin

A reinstall assigns a new internal plugin id, which means a new data directory —
settings return to defaults and any captured handshake is gone — and upstream
rules are keyed by plugin id, so re-check the Routing line.

## Capturing your own browser's handshake

Presets drift from whatever browser you actually have installed; a current
Chrome may send an extension the preset does not, which changes JA4. Capture
records your browser's real ClientHello instead.

The capture listener is a transparent pipe that sits in front of Caido, so you
point one browser's proxy at it:

```
browser → capture listener (sniffs the handshake) → Caido → target
```

Enable **Capture**, note the listen address, then start a browser pointed at it:

```
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
  --proxy-server="http://127.0.0.1:8886" ^
  --user-data-dir="%TEMP%\tls-imposter-capture" ^
  --ignore-certificate-errors ^
  --no-first-run --no-default-browser-check ^
  --disable-background-networking --disable-sync --disable-component-update ^
  "https://tls.peet.ws/api/all"
```

That is `cmd` syntax — the quoted path and `^` continuations do not work in a
WSL or PowerShell prompt.

**`--user-data-dir` must name a directory no running Chrome is using.**
Otherwise the new `chrome.exe` hands its URL to the existing instance and
discards every other flag, proxy included, and capture silently does nothing.

**Confirm what you actually captured.** `--proxy-server` sends *all* of the
browser's connections through the listener and the newest handshake wins, so
background traffic can overwrite the one you wanted. Chrome's push channel
(`mtalk.google.com`) is the usual culprit, and because it is raw TLS rather than
HTTPS its handshake carries no ALPN — selecting it gives up HTTP/2 entirely. A
usable capture has a JA4 ending in `h2`.

Then switch the fingerprint source to `captured`. The handshake is stored, so
the capture browser is only needed while capturing; turn Capture off afterwards,
and recapture when your browser updates.

## How it works

Caido's backend plugin runtime is QuickJS. It offers raw sockets but no control
over ClientHello construction or HTTP/2 framing — which is the entire point of
the plugin. So the work happens in a Go helper, shipped as a backend asset:

1. Caido matches its upstream rule and calls the plugin's `onUpstream` hook.
2. The plugin opens a loopback connection to the helper, writes a one-line
   preamble carrying that request's target, profile and timeout, and returns the
   connection to Caido.
3. The helper replays the request through `tls-client` under the chosen profile
   and writes the response back down the same socket.

Three design properties worth knowing:

- **The helper is stateless about settings.** Every connection carries its own
  configuration, so restarting it loses nothing and there is no state to resync.
- **The helper owns anything long-lived.** Caido's backend SDK has no unload
  hook, so a plugin can never release what it opens. Long-lived resources live
  in a process the plugin can kill, and the helper exits when its stdin closes,
  so it cannot outlive the plugin.
- **It fails closed.** If the helper is down, routed requests are answered with
  a 502 rather than sent with Caido's own fingerprint. A dead helper cannot
  silently leak an unspoofed request. Unexpected 502s mean "check Helper
  status", not "the plugin is broken".

## Limitations

- Response header order and casing are normalized; Go's response model does not
  preserve them.
- Responses are buffered. SSE and long-polling do not stream, slow responses hit
  the timeout, and large bodies occupy memory.
- Deliberately malformed requests cannot survive the parse and rebuild. Turn
  routing off for those hosts.
- Caido's own upstream proxy settings do not apply to routed traffic, because
  the helper opens the egress connection itself.
- JA4 encodes the negotiated ALPN, so relayed HTTP/1.1 traffic will not match
  the `h2` a browser shows.
- A captured handshake pins one extension ordering. Chrome randomizes that
  order per connection, so `captured` yields a JA3 that is stable where a real
  browser's varies — JA4 is unaffected, since it sorts extensions.
- Windows x64 only. Another platform is a `GOOS`/`GOARCH` change plus an extra
  asset.

## Credits

Built on:

- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) —
  BSD-4-clause. Its advertising clause requires that advertising materials
  mentioning features or use of this software display the acknowledgement:
  *"This product includes software developed by the copyright holders."*
- [bogdanfinn/utls](https://github.com/bogdanfinn/utls), a fork of
  [refraction-networking/utls](https://github.com/refraction-networking/utls) —
  BSD-3-clause

[sleeyax/burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls)
(GPL-3.0) solves the same problem for Burp Suite and is where the approach of
retargeting proxy traffic at a local Go server comes from. No code is shared
with it; TLS Imposter is an independent implementation against Caido's plugin
API.

Design notes, probe results and acceptance measurements live in
`docs/superpowers/specs/`.
