# Relay Platform 0.109.0 — UDP Queue and Rate Limits

Date: 28 October 2026. Baseline: 0.108.0 (`27b5eb3e1a273f26ab6bd6e21052df1bac3a8a1c`).

This development release adds queue sizing and per-association rate limiting to
the reverse mux UDP relay. It does not claim production acceptance or
completion of the 22-module product.

## Change

- `--udp-queue 16..65536` (default 1024) sets the UDP receive queue length.
- `--udp-rate-pps N` (default 0, unlimited) limits bidirectional packets per
  association with a one-second token bucket.
- Excess rate-limited datagrams are dropped and counted in
  `relay_reverse_mux_udp_rate_limited_total`.
- A full queue remains counted in `relay_reverse_mux_udp_dropped_total`.
- Fixed-target, SOCKS5 multi-target, private-target and CIDR policy behavior is
  unchanged.

## Validation

- Rust: **412 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- Existing UDP echo, SOCKS5 multi-target, private-target, allowlist and metrics
  tests rerun.

## Limits

The token bucket is per association and process-local. No Linux/WAN, real
client, browser, endurance or release-reproducibility acceptance was run. The
full 22-module product remains open.
