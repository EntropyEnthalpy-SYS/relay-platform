# Relay Platform 0.110.0 — Standalone h2c CONNECT Proxy

Date: 28 October 2026. Baseline: 0.109.0 (`b189075cb8f0ec94592a4680d6d218bb6e94a123`).

This development release adds an HTTP/2 cleartext (h2c) CONNECT forward proxy
as a standalone command. It does not claim production acceptance or completion
of the 22-module product.

## Change

- New command:
  `relay http2-connect --listen ADDR [--username USER --password PASS] [--allow-private]`
- Uses HTTP/2 prior knowledge (h2c), not HTTP/1.1.
- Requires `Proxy-Authorization: Basic ...` when credentials are configured;
  unauthorized requests get 407.
- CONNECT targets are parsed from the authority; private/loopback destinations
  require `--allow-private`.
- A successful CONNECT returns 200 and upgrades to a bidirectional byte tunnel.
- Handshake and target connect each have a 10-second timeout.
- New tests cover a private echo target and Basic auth 407/200 behavior.

## Limits

This is a standalone listener. It is not yet wired into rule-level metering,
destination ACLs, rate limits, templates or the UI. HTTP/2 over TLS with ALPN,
HTTP/2 proxy authentication schemes other than Basic, and browser/client matrix
acceptance remain open. No Linux/WAN, real client, browser, endurance or
release-reproducibility acceptance was run.

## Validation

- Rust: **414 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
