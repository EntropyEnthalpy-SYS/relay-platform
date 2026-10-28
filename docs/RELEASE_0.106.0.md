# Relay Platform 0.106.0 — UDP Idle and Drop Observability

Date: 28 October 2026. Baseline: 0.105.0 (`8fcdc57d97f76c3383398cbc4d1bcd9a33b7c452`).

This development release adds configurable idle expiry and drop observability
to the reverse mux UDP relay. It does not claim production acceptance or
completion of the 22-module product.

## Change

- `reverse-mux-server --udp-idle-secs 1..86400` (default 60) controls UDP
  association expiry.
- `relay_reverse_mux_udp_dropped_total` counts datagrams dropped because the
  client-to-server receive queue is full.
- Existing fixed-target and SOCKS5 UDP modes are unchanged.

## Validation

- Rust: **410 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- Existing UDP echo, SOCKS5 multi-target, and metrics tests rerun.

## Limits

The receive queue is fixed at 1024 datagrams. No Linux/WAN, real client,
browser, endurance or release-reproducibility acceptance was run. The full
22-module product remains open.
