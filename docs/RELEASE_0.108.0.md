# Relay Platform 0.108.0 — SOCKS5 UDP Destination Allowlist

Date: 28 October 2026. Baseline: 0.107.0 (`5f7403966a0b5777d3fe75b50bd11035ceaabc80`).

This development release adds an optional destination CIDR allowlist to the
SOCKS5 UDP multi-target mode. It does not claim production acceptance or
completion of the 22-module product.

## Change

- Repeatable `--udp-allow-cidr CIDR` on the reverse mux client.
- When non-empty, only destinations whose resolved IP is in a listed CIDR are
  allowed.
- Domain targets are resolved before CIDR and public/private policy checks.
- The existing private-target default and `--udp-socks5-allow-private` remain.
- Fixed `--udp-target` remains an explicit target and is not filtered.

## Validation

- Rust: **412 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- New regression sends a loopback target that is outside the configured
  allowlist and verifies it is not reached.

## Limits

Per-domain dynamic re-resolution and DNS rebinding after policy checks remain
open. No Linux/WAN, real client, browser, endurance or release-reproducibility
acceptance was run. The full 22-module product remains open.
