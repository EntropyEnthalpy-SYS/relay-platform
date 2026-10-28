# Relay Platform 0.99.0 — Explicit Control Limit

Date: 28 October 2026. Baseline: 0.98.0 (`c85950c87379379eff4cc7f3bacb50b44aa9b9e2`).

This development release adds an explicit per-process reverse-mux control
connection limit. It does not claim production acceptance or completion of the
22-module product.

## Change

- `reverse-mux-server --max-controls 1..65535` (default 1024).
- A control consumes a slot after token authentication and before `READY`.
  At the limit, a new authentication receives `DENY`.
- The limit is separate from:
  - 64 pending plain/TLS authentications,
  - 64 pending public TLS handshakes per control,
  - `--max-streams` per control.
- Active/total control counters remain in `relay_reverse_mux_*` metrics.

## Validation

- Rust suite: **403 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- New test starts a real `reverse-mux-server` child with `--max-controls 1`,
  authenticates one control, and verifies the second receives `DENY`.
- Existing handshake isolation, half-close, flow-control, CIDR, TLS/mTLS,
  rollout recovery, subscription and state-fence checks rerun.

## Limits

The limit is per server process, not a cluster-wide quota. No Linux/WAN, real
client, gateway/provider, browser, endurance or release-reproducibility
acceptance was run. The complete 22-module platform remains open.
