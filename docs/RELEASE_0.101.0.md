# Relay Platform 0.101.0 — Per-stream Byte Limit

Date: 28 October 2026. Baseline: 0.100.0 (`1d453bfec651c8bed09ac1f552109898ba2483a2`).

This development release adds an optional byte cap for each reverse mux stream.
It does not claim production acceptance or completion of the 22-module product.

## Change

- `reverse-mux-server --max-stream-bytes N` (default 0, unlimited).
- The limit counts DATA bytes in both directions on one stream.
- `StreamFlow::consume` uses atomic CAS shared by both bridge directions.
- Exceeding the cap cancels that stream and sends RESET to the peer; the control
  connection and neighboring streams continue.
- The cap is captured when a stream is created; changing the process setting
  does not retroactively alter active streams.
- DATA is counted in complete read/write chunks. A write that crosses the cap
  may have already delivered the preceding complete chunk; this is a resource
  guard, not billing-grade truncation.

## Validation

- Rust: **405 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- New unit test verifies shared bidirectional accounting, exact exhaustion,
  zero-byte behavior and the unlimited default.
- Existing reverse mux, flow-control, backpressure, rollout, subscription and
  state-fence checks rerun.

## Limits

No Linux/WAN, real client, gateway/provider, browser, endurance or release
reproducibility acceptance was run. The complete 22-module platform remains
open.
