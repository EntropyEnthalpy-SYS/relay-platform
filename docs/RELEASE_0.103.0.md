# Relay Platform 0.103.0 — UDP over the Reverse Mux

Date: 28 October 2026. Baseline: 0.102.0 (`6abdb796aac98b79ce7bcd3077c1afcef9676881`).

This development release adds a fixed-target UDP relay over the existing
reverse mux control connection. It does not claim production acceptance or
completion of the 22-module product.

## Change

- Server: `--udp-listen ADDRESS` (optional).
- Client: `--udp-target ADDRESS` (optional).
- Public UDP source addresses form associations. The server sends `OPEN` with
  the `udp-v1` feature and `DATAGRAM` (kind 8) frames; client target replies
  return the same way.
- Associations count against `--max-streams` and `--max-total-streams`.
  `--max-stream-bytes` counts both directions.
- Associations expire after 60 seconds of inactivity.
- A full 1024-datagram receive queue drops new datagrams; UDP is lossy by
  design.
- UDP currently requires `--max-controls 1`, because the public UDP socket has
  no control-affinity field. The public UDP listener is not encrypted by mux
  TLS; use an external encrypted tunnel if needed.

## Validation

- Rust: **408 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- Library test sends a real UDP datagram through the mux and verifies the
  echo.
- CLI test starts separate server/client processes with `--udp-listen` and
  `--udp-target`, sends a public datagram, and verifies the reply.

## Limits

No Linux/WAN, real client, gateway/provider, browser, endurance or release
reproducibility acceptance was run. UDP is currently one fixed target and one
control; multi-target UDP, per-association ACL, and encrypted public UDP remain
open. The complete 22-module platform remains open.
