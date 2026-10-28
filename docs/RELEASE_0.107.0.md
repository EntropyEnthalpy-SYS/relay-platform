# Relay Platform 0.107.0 — SOCKS5 UDP Private-target Policy

Date: 28 October 2026. Baseline: 0.106.0 (`6c97645d0ac098e64e7e113bc8a4351964975e55`).

This development release adds a default SSRF guard to the SOCKS5 UDP
multi-target mode. It does not claim production acceptance or completion of the
22-module product.

## Change

- `--udp-socks5` now rejects private, loopback, link-local and other non-public
  address targets by default.
- Domain targets are resolved by the client and only public addresses are
  selected.
- `--udp-socks5-allow-private` explicitly permits private/local targets.
- Fixed `--udp-target` remains an explicit target and is not affected by this
  filter.
- Existing SOCKS5 UDP multi-target behavior is otherwise unchanged.

## Validation

- Rust: **411 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- New regression verifies that a loopback target is not reached without the
  explicit allow flag; the existing two-target test explicitly enables local
  targets.

## Limits

DNS rebinding after resolution, IPv6 policy edge cases and per-destination
allowlists remain open. No Linux/WAN, real client, browser, endurance or
release-reproducibility acceptance was run. The full 22-module product remains
open.
