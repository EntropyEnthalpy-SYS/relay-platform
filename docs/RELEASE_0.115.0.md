# Relay Platform 0.115.0 — Non-payment development milestone

Date: 2026-10-29. This is a tested development milestone, not the completed 22-module platform or a top-tier performance certification. Payment development is excluded; existing payment code is preserved.

## What is delivered since 0.113.0

- Native Linux MPTCP inbound/outbound sockets with Off/Prefer/Require policy, strict negotiation checks, fallback diagnostics, bounded connection observations, metrics and editor fields. Endpoint administration and real multi-link bandwidth gains remain open.
- SMTP notifications with mandatory STARTTLS or implicit TLS, private CA support, bounded delivery, redacted secrets and tenant-scoped channels/history. Pending retries recheck ownership and cancel revoked jobs. Acceptance used local mail fixtures, not a real external inbox.
- Managed VLESS/TLS and Reality/Vision, Hysteria2, TUIC v5, AnyTLS/TCP, Trojan and VMess through pinned sing-box 1.14.4. One shared child serves up to 64 enabled gateway rules. Upstream source, license text and checksum-based staging tooling accompany the panel source.
- Native destination policy, private-address protection, hierarchical budgets, aggregate rates, expiry, connection/session limits and durable accounting behind authenticated loopback bridges. Source CIDRs use the real client address for authenticated business routing.
- Typed rule editor, credential generation, engine diagnostics, template public-endpoint allocation, sing-box JSON and mihomo/Clash Meta subscription exports. Reality private keys and private bridge credentials are excluded from subscriptions.
- Engine version/configuration preflight, child supervision and bounded restart, failed-update rollback, Linux parent-death handling and private temporary configuration permissions.
- CycloneDX 1.6 dependency inventory and third-party provenance. The inventory covers locked Cargo resolution plus the optional engine; it does not expand the engine's Go transitive dependency graph or constitute a vulnerability audit.

The platform owns its panel/control/accounting code. The optional protocol engine is an upstream implementation under its own license; it is not claimed as independently authored protocol code. Its bundled source includes go.mod/go.sum, not a fully vendored offline Go toolchain.

## Verification

| Check | Result |
|---|---|
| macOS arm64 full regression | 451 Rust tests, 30 Python tests, six JavaScript checks; formatting and Clippy passed |
| Linux x86_64 full regression | 451 Rust tests, 30 Python tests, six JavaScript checks; formatting and Clippy passed |
| Engine/client suite | Eight tests explicitly executed on both platforms with sing-box 1.14.4 and mihomo 1.19.33 |
| Legacy CLI regression | Eight release-binary groups passed, including old-peer compatibility, state fence, subscriptions, reverse transport and SOCKS5 history |
| Linux MPTCP | Three real kernel subflows in disposable namespaces; primary-path loss preserved the connection; 2 MiB each direction matched the durable ledger |
| Linux strict MPTCP probes | Both opt-in tests passed: required-mode negotiation and rejection of ordinary TCP peers |
| Browser | Create/edit a gateway, confirm applied revision, inspect mihomo subscription, apply a template at a different public endpoint; agent acknowledged revision 3 |
| WAN gateways | All six transferred exact 1 KiB and 1 MiB bodies; five UDP-capable protocols returned exact UDP echoes; AnyTLS remains TCP-only |

The eight protocol tests include TCP for all six protocols, UDP for five, wrong credentials, Reality/Vision with an owned TLS origin, wrong Reality keys, source/destination/private-address denial, zero quota, expiry, rate enforcement, exact application accounting for certificate-mode protocols, metered Reality camouflage, private bridge authentication, process restart and failed-update rollback. These eight overlap three default tests; do not add their full count to the full-suite total as unique tests. The default suite also reports ignored opt-in tests and a subprocess helper separately.

Browser testing used an isolated localhost controller and agent. The in-app browser does not support the native prompt used by “save as template”, so that fixture was seeded through the API; template application was tested through the browser. This is not an assertion that every panel screen or mobile client has been accepted.

## Low-spec hardware results

The actual smaller server was Debian 13 x86_64, **one vCPU, 948 MiB RAM, no swap**, with existing services still running. The larger server supplied the independent WAN client. Test services, ports and state were isolated. Load generators and origins were outside the relay cgroups, and therefore are not part of an application-memory-cap claim.

Short profiles ran native TCP/HTTP2 batches at concurrency 1/16/64, plus 24 simultaneous gateway transfers (four per protocol, 1 MiB each):

| Agent + shared engine memory cap | Complete short profile | Gateway batch |
|---|---|---|
| 64 MiB | Pass | Pass |
| 128 MiB | Pass | Pass |
| 192 MiB | Pass | Pass |
| 256 MiB | Pass | Pass |

The sustained profile used a 64 MiB controller cap and a 192 MiB agent-plus-engine cap, sharing the server's one CPU, with swap disabled for the services and a 128 KiB per-direction socket-buffer request. **All 192 transfers passed across three independent rounds of 64 concurrent HTTP/2 readers**, each transferring 16 MiB. The three rounds took 194.63 seconds in total (132.40 Mbps aggregate). Each reader was deliberately limited to 256 KiB/s. During that run, agent-cgroup peak was 84.16 MiB and controller-cgroup peak was 24.43 MiB. The follow-on HTTP/2 soak lasted 600.02 seconds and completed 292 transfers without failure. Six managed gateways stayed configured, but this periodic soak does not establish long-duration mixed-protocol reliability.

Cgroup charged memory is not summed process RSS or whole-machine RAM. Shared executable pages and page-cache ownership can make these measures differ. The evidence includes process membership/RSS and cgroup samples. The optional engine is inside the agent's cgroup; its GOMEMLIMIT is only a garbage-collection target.

**Practical starting point supported by this run:** a 1-vCPU/1-GiB Linux VPS, with 64 MiB reserved for this small controller workload and 192 MiB for the agent plus optional engine, plus OS/service headroom. The lower 64 MiB agent cap passed short batches only. These results do not certify the mathematical minimum, a 512 MiB whole VM, thousands of users, large rule inventories, or sustained peak WAN throughput. The local goodput above is an intentionally rate-limited workload, not the network's maximum rate.

## Issues discovered and resolved during acceptance

1. MPTCP editing could drop fixed-target health settings; the submission path now preserves both, covered by the form regression.
2. Applying a gateway template retained its source public endpoint; application now uses the requested public address and allocates a distinct private bridge, covered by persistence tests and browser acceptance.
3. mihomo can bind its SOCKS port before forwarding is enabled. The test now waits through a fixture-only DIRECT echo route. Twenty-five repeated client-suite runs passed. Actual protocol transfers are not retried to hide failures.
4. Reality's camouflage dialer could bypass the native accounting path. It now uses the authenticated bridge. Its opaque TLS/fallback bytes are charged to the same budgets, and plain TLS fallback probes confirm zero quota and destination denial are enforced.
5. The inter-VPS path reported a 1,280-byte MTU. Initial QUIC defaults produced oversized packets; packet-header traces showed smaller replies arriving while larger initial replies were absent. Servers and sing-box client exports now start at a 1,200-byte QUIC payload; path MTU discovery remains enabled. Final WAN probes passed for Hysteria2 and TUIC as well as the other protocols.

6. The earlier 32 KiB socket-buffer suggestion was withdrawn from the UI and current HTTP/2 guide. Both the 0.114 and 0.115 small-VPS tests had intermittent slow-reader timeouts with that setting despite no OOM. Increasing the origin backlog alone did not resolve them. A separate reproduction captured heavy retransmissions, a 1,024-byte MSS and severely reduced TCP pacing on the stalled connection under the host's BBR configuration. Larger 128 KiB buffers passed the comparison and final workload without modifying host sysctls. This is a validated operating profile for this workload, not proof of a universal kernel fix or universal minimum buffer; the product default remains OS autotuning.

Earlier failures, the 32 KiB reproduction and the buffer-sizing comparison are retained separately. No transfer retries or increased transfer deadlines turn failed cases into passes. An MPTCP runner initially omitted /usr/sbin from PATH; the corrected runner passed and removed its namespaces.

## Operational limits and remaining delivery gates

- Applying a gateway generation restarts the shared protocol engine and interrupts its connections. This is not a zero-downtime reload. Unexpected exits restart automatically; abrupt parent crashes may leave private configuration files requiring secure cleanup.
- Public source ACLs run after protocol authentication/routing. They are not a pre-TLS firewall and do not filter Reality camouflage by original client address. The camouflage destination, quota, rate and connection bounds do apply. Other unauthenticated handshake resource usage still needs host ingress protections and workload sizing.
- Allow the Reality camouflage destination in the destination policy; its bytes count toward quotas. Client verification stays enabled. Other clients control their own initial QUIC packet size; mihomo WAN behavior on this constrained-MTU path has not been certified.
- Native 0.114 and pre-MTU 0.115 observations are historical evidence, not substitutes for the final source/binary checks. Binary checksums, final source-input fingerprints and archive inventories identify the delivered build. Engine source-build instructions are included; byte-identical reproducibility across independent builders is not established.
- Finish MPTCP endpoint management, ACME/certificate lifecycle, adaptive path/cost/capacity selection, remaining protocol targets, object-level permissions and non-financial entitlements, WireGuard/P2P, DNS provider acceptance/webhooks, GeoIP/ASN policies, cross-panel sharing, bulk lifecycle operations, longer history/automation and clean disaster-recovery/migration acceptance.
- A test domain and authorized DNS/CA staging configuration are still needed. External SMTP inbox delivery, remaining licensed clients, Linux ARM64/OpenRC and complete browser/mobile-client coverage remain open.
- Run the 72-hour mixed-load/failure/recovery gate and comparable direct/competitor benchmarks under the same hardware and security conditions. No top-tier or best-price/performance claim has been demonstrated.

The complete English non-payment target checklist is [NONPAYMENT_TARGETS_EN.md](NONPAYMENT_TARGETS_EN.md). The original scope remains in [REQUIREMENTS.md](REQUIREMENTS.md), with current workstreams in [NONPAYMENT_DELIVERY.md](NONPAYMENT_DELIVERY.md). See [PROTOCOL_GATEWAYS.md](PROTOCOL_GATEWAYS.md) for installation, licensing, accounting and client configuration. Existing production services were not upgraded by these tests.
