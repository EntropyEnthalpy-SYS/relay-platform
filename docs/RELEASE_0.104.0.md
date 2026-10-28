# Relay Platform 0.104.0 — Public TLS Client Certificates

Date: 28 October 2026. Baseline: 0.103.0 (`0cc5f7882897b78b54e18d294c64e2d5bb9b3581`).

This development release adds optional mutual TLS on the reverse mux public
listener. It does not claim production acceptance or completion of the
22-module product.

## Change

- New `reverse-mux-server --public-tls-client-ca CA`.
- It requires `--public-tls-cert` and `--public-tls-key`; the CA verifies the
  public client certificate.
- The public mTLS requirement is independent of control-plane TLS/mTLS.
- Existing public TLS, public CIDR, handshake isolation, and UDP behavior is
  unchanged.

## Validation

- Rust: **409 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
- Test covers a public TLS client without an identity (no usable tunnel/no
  echo) and a client with an identity (echo succeeds).

## Limits

No Linux/WAN, real client, browser, endurance or release-reproducibility
acceptance was run. Public UDP remains plaintext. The full 22-module product
remains open.
