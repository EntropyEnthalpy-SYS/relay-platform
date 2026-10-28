# Relay Platform 0.113.0 — Managed HTTP/2 and Linux Acceptance

Date: 2026-10-28. Status: development release, with measured single-host acceptance.

HTTP/2 CONNECT is now integrated into the controller, agent and rule engine. Real Linux, curl, Chromium and public-network probes have been performed. The result supports a small **application resource budget for a defined workload**; it does not establish a universal minimum VPS specification or complete the full platform roadmap.

## Delivered functionality

| Area | What this release provides |
|---|---|
| Managed HTTP/2 | TCP rules with `inbound_http2_connect`, controller revisions, agent synchronization and templates. Existing standalone CLI entry points remain available. |
| Accounting and quotas | Reuses the ordinary relay copy path, persistent upload/download accounting, combined quotas and existing hierarchical budget checks. Counts application payload, excluding HTTP/2 framing and TLS overhead. |
| Access policy | Source ACLs, destination IP/CIDR/domain/port policy, private-address protection, outbound binding and rule expiry. |
| Rate and concurrency | Existing rule/owner/node throttles; a stream limit shared across connections and listen ports; a separate physical TCP connection limit. |
| Authentication | Optional Basic credentials and up to eight SHA-256 Bearer digests, constant-time digest comparison, rotation overlap and revocation by configuration update. Tokens belong to a rule owner, not individual billing accounts. |
| TLS | HTTP/2 ALPN enforcement and existing certificate profiles, including optional mutual TLS. Cleartext prior-knowledge HTTP/2 remains available for controlled networks. |
| Lifecycle | Rule disable, security configuration changes, expiry, idle timeout and engine shutdown release tunnel tasks and resource permits. |
| Panel and telemetry | Managed rule editor, token generation, TLS fields, stream/socket-buffer controls, template serialization, active stream statistics and a Prometheus gauge. |
| Low-memory controls | Optional TCP send/receive buffer requests on both sides of managed HTTP/2 tunnels. OS autotuning remains the default. |
| Acceptance tooling | Isolated systemd/cgroup capacity lab and Chromium panel/proxy checks, included in source. |

See [HTTP2.md](HTTP2.md) for configuration, credential handling and client limitations. Other standalone subsystems are not automatically integrated by this HTTP/2 change. The [full requirements](REQUIREMENTS.md) and [module status](STATUS.md) remain in force.

## Regression evidence

The verification package contains raw logs, structured measurements, source inventory, checksums, a screenshot and reproduction instructions.

| Check | Result |
|---|---|
| macOS arm64 Rust suite | 434 passed, zero failed, across 41 test executables; one explicitly ignored crash-helper entry point is invoked by its parent test. |
| Linux x86_64 Rust suite | 434 passed, zero failed, with the same crash-helper convention. |
| Deployment tests | 29 passed on each platform. Linux uses the optimized release binary. |
| Formatting and lint | `cargo fmt` and Clippy with warnings denied passed. |
| JavaScript | Application syntax and three assertion scripts passed. |
| Managed HTTP/2 tests | Eight tests cover authentication, metering/quota, shared stream limits, ACLs, throttling, credential rotation, TLS/mTLS/ALPN, lifecycle cleanup and templates. These are included in the Rust total. |
| Previous review probes | All four 0.111 review acceptance probes passed again; they are included in the Rust total. |
| Release CLI regression groups | Eight groups passed on macOS: rollout recovery, reverse multiplexing, backpressure, old-peer compatibility, state fencing, subscriptions, historical SOCKS5 behavior and reverse UDP compatibility. |
| Real panel | Chromium login, rule rendering, editor preservation, publishing, token generation/rotation and API persistence passed. |
| Real proxy clients | Linux curl Basic/Bearer probes, macOS curl over a public route, and Chromium HTTPS browsing through the proxy passed. |

Linux exposed two assumptions in existing test fixtures: small default UDP receive buffers and a CLI client starting before its server was ready. The fixtures now size their receive queues explicitly, pace their test bursts and wait for server readiness and probe cleanup. No production UDP forwarding behavior was changed for those fixture repairs. The affected test groups passed again locally, and the Linux full suite covers the final fixtures.

An initial Linux deployment-test setup rejected the 316 MiB debug binary under the existing 256 MiB bundle limit. The roughly 25 MiB optimized binary passes the deployment tests. The verifier now builds/selects a release binary by default; the bundle size guard remains unchanged. Early failed measurements are described separately from final passing runs.

## Hardware and workload

The actual host was a Debian 13.7 x86_64 VPS with four AMD EPYC-Turin virtual CPUs and 7,943 MiB RAM. It also carried an existing 0.19.0 controller/agent and other services. Those services were preserved. Test state, binaries, certificates and systemd unit names were isolated.

Both tested application processes were pinned to CPU 0. Each had a 100% CPU quota, `MemorySwapMax=0`, one Tokio worker, and a separate memory cap. Thus the controller and agent shared one logical CPU. Load generators, local origins, the operating system and unrelated services were outside these application caps. Builds ran separately with a two-CPU quota and a 3 GiB memory cap. This is not equivalent to booting a 1-vCPU/128-MiB VM.

The final HTTP/2 test rule used TLS, a 128-stream limit, a 256-connection limit and `socket_buffer_bytes=32768`. The OS may round/double the requested buffer sizes. A cgroup measures charged memory, including relevant kernel allocations; RSS includes resident mappings and can differ. Both are recorded.

| Profile / workload | Observed result | What it establishes |
|---|---|---|
| Controller capped at 64 MiB | Started and remained available; 100 local node-list requests had p95 latency 1.27 ms. | Fits the small test state and request workload. Does not cover large user/rule inventories. |
| Agent capped at 16 MiB | Failed during the 64-connection TCP batch. | Not a supported budget for this workload. |
| Agent capped at 32 MiB | Passed six short TCP/HTTP2 batches: 1, 16 and 64 simultaneous requests, 4 MiB each. | A short-batch result only, not a sustained minimum. |
| Agent capped at 64 and 128 MiB | Passed all six short batches at each cap. | Headroom for the tested batch profiles. |
| Controller 64 MiB + agent 64 MiB, shared CPU 0 | All 64 simultaneous HTTP/2 slow-reader transfers passed: 16 MiB per transfer, 1 GiB total, 80.13 seconds, 107.20 Mbps aggregate. Each client was limited to 256 KiB/s. | A demonstrated 128 MiB combined application cap for this defined loopback workload. The measured goodput is not peak link capacity. |
| Agent memory during that 64-transfer workload | Peak cgroup memory 37.50 MiB; process high-water RSS 42.57 MiB; no OOM events. | Bounded socket settings materially help this workload. |
| Ten-minute follow-on soak | 600.94 seconds, 291 transfers of 1 MiB, zero transfer failures or OOM events. Agent RSS went from 40.35 to 39.69 MiB. | Short stability evidence, not a 72-hour endurance result. |

During the soak, an additional comparison listener was configured; agent file descriptors changed from 17 to 18. This is not presented as a fixed-configuration leak test. Controller cgroup peak over the measured steady/soak period was about 48.01 MiB; its process high-water RSS was 55.50 MiB.

### Memory versus WAN throughput

An exploratory run using automatic TCP buffers exhausted the agent's 64 MiB cgroup under 64 slow readers. The final bounded-buffer run passed. However, small buffers also reduced throughput on the tested public route:

| Public-route setting | Three 4 MiB transfers, median payload rate |
|---|---:|
| 32 KiB per-direction socket buffer request | 2.79 Mbps |
| OS automatic TCP buffers | 14.39 Mbps |

All six successful samples verified payload size and SHA-256. They used the same macOS-to-VPS route and origin, in sequential runs. The automatic-buffer samples ran after restarting the isolated lab. These short samples show a roughly 5.2× difference on that route; they do not measure the server's maximum WAN capacity. Do not select the smallest buffer globally without measuring the bandwidth/latency requirement.

## Minimum configuration conclusion

**Demonstrated application budget:** one shared virtual CPU, a 64 MiB controller cap and a 64 MiB agent cap, for the specific small-state workloads above. The 32 MiB agent result is only a short-batch result; 16 MiB failed.

**Whole-VPS minimum remains unverified.** A 1-vCPU/512-MiB clean VM is a sensible next test target, not a certified requirement from this experiment. Its acceptance must include OS memory, service supervision, state/log growth, management operations, socket memory, upgrade/rollback and the intended network workload. Build memory and disk requirements are separate from runtime requirements.

For a memory-constrained starting profile, test `max_connections=64`, `max_concurrent_streams=64`, `socket_buffer_bytes=32768` with application caps of at least the measured 64 MiB per role. For longer-latency or faster WAN targets, compare larger buffers or autotuning and increase the measured memory budget accordingly. None of these settings establishes performance at thousands of concurrent tunnels.

## Remaining gates before a top-tier delivery

1. Test an actual low-memory VM at the intended bandwidth and connection counts, with sustained load and representative panel state. Establish both idle and loaded resource limits and preserve safety headroom.
2. Run at least 72 hours of mixed TCP/UDP/TLS traffic, churn, slow readers and controller operations. Record error rates, p95/p99 latency, CPU, memory, file descriptors, queueing, data integrity and accounting reconciliation.
3. Run multiple Linux hosts over real links: loss, delay, partition, controller outage, restart, certificate/credential rotation, failover, upgrade and rollback. A single-host test cannot certify those behaviors.
4. Expand the client matrix beyond the tested curl and Chromium paths. Test the intended desktop/mobile proxy clients, additional browsers and ARM64 Linux. Ordinary HTTP forward-proxy GET, OAuth/OIDC and individual Bearer-token billing are not implemented here.
5. Benchmark against direct forwarding and the chosen competitor on the same hardware, network conditions, security settings and workload. No best-in-class or best-price/performance claim has been demonstrated.
6. Close every outstanding item in the complete module checklist, including production deployment, recovery, operations and commercial workflow acceptance. Freeze a release candidate, audit dependencies and publish reproducible build/provenance evidence.

The existing installation was not upgraded by this acceptance run. Temporary lab listeners and source-restricted firewall access were stopped/removed after testing. The delivery includes the new source, a verification archive and a Linux x86_64 executable package. The executable was tested on Debian 13.7; its highest referenced glibc symbol is 2.34, which is a linkage observation rather than a certification of every newer distribution.
