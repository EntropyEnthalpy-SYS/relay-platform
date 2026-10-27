# Relay Platform 0.97.0 — Stabilization Delivery

Date: 28 October 2026. Baseline: 0.96.0 (`cc5c36692b9dde1a10a4c42b35a229019689157a`).

This development release fixes all four findings from the 0.96 review and adds permanent regressions. The complete product requirements remain open; this release is not a claim that all 22 modules have reached production acceptance.

## Corrections

| Finding | Delivered behavior | Evidence |
| --- | --- | --- |
| R96-01: retry skips a published but unqualified canary | Retry revisits the original ordered cohort. Existing rule IDs and revisions are reused, the failed canary must pass its gates before later nodes advance, and publication, receipt, health and completion are recorded separately. A persisted retry chain survives restart and returns the same completed report on repeat requests. Concurrent retries on the same root are rejected. | Store tests and `check_rollout_recovery.py`: rollback enabled/disabled, application error, missing receipt/health timeout, restart, repeated retry, no duplicate rules, pinned template content and safe handling of failed rollback. |
| R96-02: a later revision can approve an earlier canary | Both desired and applied revisions must equal the intended revision, with no apply error. A superseding configuration aborts the gate even when it retains the same rule ID and has fresh healthy telemetry. | Store tests cover receipt-only and health gates. The HTTP probe edits revision 2 into revision 3 with a different target, observes the abort and confirms the next node stays at revision 1. |
| R96-03: one blocked mux stream stalls its neighbors and ignores cleanup | New peers negotiate a bounded credit window per stream. The shared reader never waits on a full stream queue. Socket writes and credit waits are cancellable; idle/stall deadlines apply during blocked I/O. Half-close remains duplex. Abandoned partial control frames close the control rather than corrupting subsequent frames. | Rust tests include 8 MiB upload plus 8 MiB EOF-triggered reply, full queues, cancellation in both roles, blocked-write deadlines and partial-frame abandonment. Actual CLI probes cover slow public readers and slow targets, unrelated echo traffic and zero active streams after cleanup. |
| R96-04: established TLS controls occupy handshake permits | A permit covers pending TLS and token authentication, then is released after READY. It is not retained for the authenticated session. | Rust and actual CLI checks hold 80 authenticated controls open concurrently. A separate test fills 64 pending authentications, rejects another and proves a failed authentication returns a slot. |

## Validation performed

All commands completed successfully on macOS 27.0.1, arm64, Apple M1 Pro, 32 GiB RAM. Toolchain: Rust/Cargo 1.99.1, Python 3.12.14, Node 24.19.0. Subscription format parsing also used the installed Python 3.14 environment with PyYAML.

| Check | Result |
| --- | --- |
| `sh scripts/verify.sh` | Pass |
| Rust tests | **400 passed, 0 failed, 1 ignored subprocess helper**, across 38 test executables; serial execution |
| Python deployment tests | **29 passed** |
| JavaScript | Syntax check and two assertion scripts pass |
| Formatting and Clippy | Pass; Clippy warnings treated as errors |
| Optimized release build | Pass; reports 0.97.0, controller schema 5, controller/agent state contracts 2 |
| R95 and R96 targeted CLI checks | Rollout permissions/recovery, exact revision gates, mux half-close, metrics, silent TLS isolation, capacity and backpressure pass |
| 0.96 mux compatibility | Both new-server/old-client and old-server/new-client pairs preserve a 32 KiB request and EOF-triggered response |
| Earlier SOCKS5 regressions | All four socket-level probes pass |
| Subscriptions | Four formats, preview filtering, rotation and deletion pass |
| 0.19 state compatibility | Migration, recovery continuity, schema-v4 restore, MFA/token protections and old-binary refusal pass |

The rollout HTTP probe uses a real controller and seeds simulated agent receipts/health into its temporary SQLite database. Mux tests use real TCP/TLS sockets and CLI processes. These are correctness checks, not WAN performance benchmarks. The verification package contains the full logs, commands, JSON results, source inventory and artifact hashes; no old performance result is promoted to current acceptance evidence.

## Upgrade and operational notes

- Upgrade **both mux endpoints** to enable per-stream flow control. The OPEN/OK feature payload negotiates `flow-control-v1`; WINDOW is frame kind 7 with a four-byte credit count. Each direction starts with 32 DATA-frame credits. Older peers use the original exchange; a saturated legacy stream is reset individually rather than blocking the shared reader. Compatibility testing does not claim legacy peers gain the new flow-control behavior.
- The public socket stall deadline follows `--idle-timeout-secs`; the client target write stall deadline is 30 seconds. Control-frame writes, including lock acquisition, have a 5-second deadline. A broken or stalled shared control still affects all of its streams.
- The rollout response's legacy `applied` field means configuration publication. Use `acknowledged`, `healthy` and `completed` for the selected gates; `reused` identifies resumed publication. Without receipt/health gates, completion only certifies publication.
- New rollouts pin template versions. Old records deserialize with default values for the new fields. An old unpinned record whose template has advanced beyond v1 is rejected for manual reconciliation instead of guessing its original contents. A superseded node revision likewise requires reconciliation.
- Recovery covers attempts whose reports were persisted. A process crash during publication before a complete report is saved still requires reconciliation; this release does not promise exactly-once recovery for that window.
- UI results retain a retry action after every failed attempt and explain the status fields. No interactive browser acceptance was performed.

## Reproducing the checks

From the source root, with Rust, Node and Python available:

```sh
sh scripts/verify.sh
cargo build --locked --release
python3 scripts/check_rollout_recovery.py --binary target/release/relay --output rollout.json
python3 scripts/check_reverse_mux.py --binary target/release/relay --output mux.json
python3 scripts/check_reverse_backpressure.py --binary target/release/relay --output backpressure.json
```

The verification package's reproduction script also covers subscriptions and, when supplied with older binaries, compatibility and state fences. On the review host, `DYLD_LIBRARY_PATH` pointed to the local Rust toolchain's `lib` directory so its stripping tool could find LLVM. The release build completed without a stripping warning.

Linux deployment, real WAN/NAT environments, sustained load, endurance, full browser interaction and remaining product requirements still require separate acceptance. The tested release executable is macOS arm64; the source ZIP is not a prebuilt Linux deployment bundle.
