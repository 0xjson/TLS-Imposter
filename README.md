# Awesome TLS for Caido

Makes Caido's outbound HTTPS requests carry a real browser's TLS (JA3/JA4) and
HTTP/2 fingerprint, so authorized security testing of WAF-protected targets
reflects how those targets behave for a browser.

Inspired by [burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls).

> **Status: in development.** Phase 0 (probing Caido's `onUpstream` behavior) is
> complete; the Go helper and the real plugin are not built yet. See
> `docs/superpowers/plans/2026-10-03-caido-awesome-tls.md`.

## Requirements

- Caido **>= 0.55.0** (first version with `sdk.events.onUpstream`)
- Windows x64
- Go 1.26 and pnpm, to build from source

## Build

```bash
pnpm install
pnpm build          # cross-compiles the Go helper, then bundles the package
```

The result is `dist/plugin_package.zip`. Install it in Caido with
**Plugins → Install from file**.

## Credits

- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) — BSD-4-clause
- [bogdanfinn/utls](https://github.com/bogdanfinn/utls), from
  [refraction-networking/utls](https://github.com/refraction-networking/utls) — BSD-3-clause
- [sleeyax/burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls) — GPL-3.0, design inspiration

Full credits, licensing notes and known limitations are written up in Task 19.
