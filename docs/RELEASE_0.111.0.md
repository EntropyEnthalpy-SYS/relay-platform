# Relay Platform 0.111.0 — HTTP/2 over TLS/ALPN

Date: 28 October 2026. Baseline: 0.110.0 (`6377f35e13bee1e976be3b103be7dd311d803688`).

This development release adds TLS with ALPN `h2` to the standalone HTTP/2
CONNECT proxy. It does not claim production acceptance or completion of the
22-module product.

## Change

- `relay http2-connect` accepts:
  - `--tls-cert CERT`
  - `--tls-key KEY`
  - optional `--tls-client-ca CA` for client-certificate verification
- TLS accepts ALPN `h2`; cleartext h2c remains available when no TLS flags are
  supplied.
- TLS handshake and CONNECT target connect each have a 10-second timeout.
- New real h2 client test verifies a private echo target over TLS.

## Limits

The command remains standalone; rule-engine metering, ACLs, rate limits,
templates and UI integration are still open. HTTP/2 proxy authentication is
Basic only. No Linux/WAN, browser matrix, endurance or release-reproducibility
acceptance was run.

## Validation

- Rust: **415 passed, 0 failed, 1 ignored subprocess helper**.
- Python: **29 passed**.
