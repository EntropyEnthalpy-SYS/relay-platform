# Relay Platform 0.105.0 — SOCKS5 UDP Multi-target Mode

Date: 28 October 2026. Baseline: 0.104.0 (`88ca4f35d22a3727c83f00194f1e4e167810691a`).

This development release adds a multi-target UDP mode to the reverse mux.
It does not claim production acceptance or completion of the 22-module product.

## Change

- Client `--udp-socks5`:
  - public datagrams are parsed as SOCKS5 UDP requests
    (`RSV`, `FRAG`, `ATYP`, destination, payload);
  - nonzero FRAG is rejected;
  - one association can reach multiple destinations;
  - target replies are wrapped with the actual source address;
  - destinations are resolved by the client.
- `--udp-socks5` and `--udp-target` are mutually exclusive.
- The server protocol is unchanged; it forwards opaque datagrams.
- UDP still requires `--max-controls 1`; public UDP remains plaintext.

## Validation

- Rust: **410 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- Library test sends SOCKS5 UDP requests to two different echo targets through
  one mux association and verifies both wrapped replies.

## Limits

No Linux/WAN, real client, browser, endurance or release-reproducibility
acceptance was run. UDP fragmentation, public UDP encryption, per-association
ACL and multi-control UDP remain open. The full 22-module product remains open.
