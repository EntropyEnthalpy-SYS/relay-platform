# Relay Platform 0.112.0 — HTTP/2 and mux UDP correctness fixes

Baseline: 0.111.0, commit `3c6be5d973f0ea7ce30786abe220c4242357f4ff`.

This development release fixes the four independently reproduced R111 findings.
The complete 22-module platform remains in development.

## Changes

- **R111-01 — HTTP/2 lifetime:** the ten-second deadline now covers the client's
  connection preface and complete initial SETTINGS frame. Hyper then owns the
  established connection without a fixed lifetime limit. TLS establishment keeps
  its separate ten-second deadline. Each CONNECT's DNS resolution and TCP dial
  share a ten-second deadline; a failed request does not end neighboring streams.
- **R111-02 — UDP isolation:** every mux UDP association has a cancellable worker
  and a 32-datagram inbound queue. The shared frame reader only dispatches packets;
  setup, hostname lookup, sends and replies run in the worker. Setup and each
  resolution/send operation have five-second deadlines. Queue overflow drops
  datagrams instead of blocking unrelated TCP/UDP streams. There are at most 1024
  client UDP workers per control, matching the server's maximum per-control stream
  limit; duplicate or excess active UDP OPEN IDs terminate the invalid control.
- **R111-03 — reply validation:** SOCKS5-mode UDP resolves each destination once,
  applies its private-address/CIDR policy to the selected IP, and sends to that
  same endpoint. Replies are accepted only from endpoints admitted by an outgoing
  request on that association. At most 256 IP/port pairs are retained. Each entry
  expires 60 seconds after its last admitted request; unsolicited replies cannot
  refresh it. New destinations at capacity are dropped until space expires.
- **R111-04 — failed association cleanup:** server-side UDP peer/id mappings and
  their stream permits are shared with the control-frame reader. FAIL, FIN and
  RESET release them immediately, independently of the bounded reply queue.
  Registration happens before OPEN is written, covering immediate failures.
  Idle expiry and control shutdown also release the same state and permits.

The public CLI flags, UDP `udp-v1` OPEN feature and frame encoding remain
compatible. No new mandatory UDP acknowledgment is introduced. Upgrade both mux
peers to obtain all corrections: reply validation and worker isolation are on the
client; prompt admission cleanup is on the server.

## Regression coverage

The four original review acceptance probes are retained in
`tests/review_0111_probes.rs`. Additional tests exercise simultaneous h2c/TLS
connections with multiple streams for over 30 seconds, HTTP/2 half-close,
incomplete and oversized SETTINGS, DNS timeouts with a healthy neighboring
stream, full UDP queues, RESET during a held lookup, endpoint expiry/capacity,
FAIL/FIN/RESET with a full return queue, and fixed-target setup failure.

The verification package contains the final full-suite log, an explicit rerun of
the four acceptance probes, optimized-build identity, release CLI regressions,
source inventory and checksums. It also includes the original failing-before
observations under a clearly labeled baseline directory.

## Observed validation

- Full suite: **426 Rust tests passed, 0 failed, 1 ignored subprocess helper**;
  **29 Python deployment tests passed**; JavaScript syntax and both assertion
  scripts passed. Formatting and Clippy with warnings denied passed.
- The four original R111 probes passed again in a separate run. They are already
  included in the 426 Rust total; the rerun is not added to that count.
- Optimized macOS arm64 release build passed. All **eight release CLI regression
  groups** passed, covering rollout recovery/revision gates, mux metrics and
  half-close/TLS admission, backpressure isolation, 0.96 TCP compatibility,
  0.19 state migration/downgrade protection, subscriptions, historical SOCKS5
  regressions, and fixed-target/SOCKS5 UDP compatibility with 0.111 in both roles.
- The original acceptance probe file is unchanged apart from rustfmt formatting;
  its provenance check is included in the verification package.

## Scope

Validation is local macOS arm64. Current Linux/systemd/OpenRC, WAN/NAT, long
endurance and production performance acceptance remain pending. HTTP/2 remains
standalone; controller rule-engine metering, ACLs, rate limits, templates and UI
integration are still open. The mux UDP destination socket remains IPv4 in this
release. Operating-system DNS work may finish in a background blocking thread
after cancellation; no canceled worker can forward the resulting packet.

The pre-existing, uncommitted HTTP/2 connector refactor in the main checkout was
preserved separately. This release is based on the reviewed 0.111.0 commit.
