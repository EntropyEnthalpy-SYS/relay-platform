# Relay Platform 0.100.0 — Process-wide Stream Limit

Date: 28 October 2026. Baseline: 0.99.0 (`2dec8eeb46ffd3b08f14c92e1a3909217d8ee455`).

This development release adds an explicit process-wide public stream limit to
the reverse mux. It does not claim production acceptance or completion of the
22-module product.

## Change

- `reverse-mux-server --max-total-streams 1..1000000` (default 4096).
- `ActiveStream` reserves the process-wide slot and the per-control
  `--max-streams` slot with atomic CAS operations.
- If either slot is full, the public connection is closed before OPEN.
- The process-wide limit is separate from:
  - `--max-controls`,
  - 64 pending plain/TLS authentications,
  - 64 pending public TLS handshakes per control,
  - `--max-streams` per control.
- `relay_reverse_mux_streams` continues to show process-wide active streams.

## Validation

- Rust: **404 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- New test starts a real server/client pair with `--max-total-streams 1`,
  verifies the first stream reaches the backend, and verifies the second public
  stream is closed.

## Limits

The limit is per process, not a cluster-wide quota. No Linux/WAN, real client,
gateway/provider, browser, endurance or release-reproducibility acceptance was
run. The full 22-module product remains open.
