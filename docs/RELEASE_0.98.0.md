# Relay Platform 0.98.0 — Mux Handshake Isolation

Date: 28 October 2026. Baseline: 0.97.0 (`d05930ec5c4489ddca23caf8da28e4ca65cd4837`).

This development release fixes the two mux availability defects found in the
0.97 delivery review. It does not claim production acceptance or completion of
the full 22-module product.

## Corrections

| Finding | Delivered behavior |
| --- | --- |
| Plain control authentication blocked accepts | Plain `REVERSE-MUX` authentication runs in an isolated task. A silent plaintext control no longer holds the accept loop; pending plain authentications are bounded at 64 per process with a 10-second deadline. |
| Public TLS handshake blocked sibling public accepts | Public TLS negotiation runs in an isolated task with a 10-second deadline and at most 64 pending public handshakes per authorized control. A silent public TLS client no longer stops another public client on the same control. |
| Concurrent OPEN could exceed the stream cap | `open_public_stream` reserves a stream slot with an atomic CAS before OPEN. The per-control stream cap is enforced across concurrent public tasks, not only in the accept loop. |

The existing half-close, flow-control, CIDR, control TLS/mTLS, and metrics
behavior is unchanged.

## Validation

| Check | Result |
| --- | --- |
| `sh scripts/verify.sh` | Pass |
| Rust tests | **402 passed, 0 failed, 1 ignored subprocess helper** |
| Python deployment tests | **29 passed** |
| JavaScript | Syntax check and two assertion scripts pass |
| Formatting and Clippy | Pass; warnings denied |
| Optimized release build | Pass; 0.98.0, controller schema 5, state contracts 2 |
| New regressions | Silent plaintext control does not block a legitimate READY; silent public TLS does not block a neighboring public echo |
| Previous checks | 0.97 rollout/mux/backpressure/compatibility, subscriptions and 0.19 state fence rerun |

The new tests are loopback correctness tests. No Linux, WAN/NAT, real client,
gateway/provider, browser, long endurance or independent release-reproducibility
acceptance was performed.

## Operational notes

- Plain control pending-auth capacity is 64 per server process; a full capacity
  closes new unauthenticated controls rather than queueing them indefinitely.
- Public TLS pending-handshake capacity is 64 per authorized control. The
  control's public accept loop continues while handshakes run.
- The public TLS handshake task holds its permit only until the handshake ends;
  it does not consume a stream slot until OPEN succeeds.
- `max_streams` remains per authorized control. There is no global stream or
  connection limit; configure and monitor the deployment externally.
- The mux control reader remains shared. A stalled control write can affect all
  of its streams, as documented previously.

## Reproduce

```sh
sh scripts/verify.sh
cargo build --locked --release
python3 scripts/check_reverse_mux.py --binary target/release/relay --output mux.json
python3 scripts/check_reverse_backpressure.py --binary target/release/relay --output backpressure.json
```

## Scope

Still open: Linux/WAN acceptance, reverse UDP, WireGuard, MPTCP data path,
federation, commerce entitlement execution, browser acceptance, persistence,
and 72-hour/30-day endurance. Business work remains deferred.
