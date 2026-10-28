# Relay Platform 0.102.0 — Limit Observability and Byte-limit E2E

Date: 28 October 2026. Baseline: 0.101.0 (`307485b80d9b7590b0dc91e4f194fdb49b98ed05`).

This development release makes the new mux limits observable and adds a real
CLI end-to-end regression for the per-stream byte cap. It does not claim
production acceptance or completion of the 22-module product.

## Change

- New process-local Prometheus counters:
  - `relay_reverse_mux_control_limit_rejections_total`
  - `relay_reverse_mux_stream_limit_rejections_total`
  - `relay_reverse_mux_stream_byte_limit_resets_total`
- `--max-stream-bytes 1` CLI regression:
  - first byte reaches the backend;
  - second byte causes only that stream to reset;
  - later reads on the public side end.
- Counters are process-local and reset on restart; they are not persisted.

## Validation

- Rust: **406 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- The byte-cap test uses separate server/client processes and a real TCP
  backend, not only a unit-level counter.

## Limits

No Linux/WAN, real client, gateway/provider, browser, endurance or release
reproducibility acceptance was run. The complete 22-module platform remains
open.
