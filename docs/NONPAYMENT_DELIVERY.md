# Non-payment platform completion

Requested scope: complete the remaining platform functionality and acceptance, excluding payment work. Started 2026-10-29 from 0.113.0, commit `0dfff2993fd7e110079c7e98b4cdd965d9d1e985`.

Payment gateways, money movement, refunds, commissions and payment reconciliation are excluded from this delivery. Existing payment code is preserved. Non-financial access entitlements, quotas, permissions, subscriptions, announcements and support workflows remain in scope.

## Completion contract

An item is complete only when its data model, authorization, API, persistence, node execution, applicable UI and meaningful acceptance checks exist. A protocol name, checkbox, generated configuration or external binary alone is not interoperability evidence. Native implementation and optional third-party integration must be identified separately, with source/license provenance.

Use `REQUIREMENTS.md` for the complete original scope. Historical `STATUS.md` entries must be reconciled with current code: managed HTTP/2 and reverse UDP are already implemented, but their existence does not close the entire multi-protocol or networking module.

## Work sequence and evidence gates

| Workstream | Implementation required | Acceptance required | Current state |
|---|---|---|---|
| MPTCP | Real inbound/outbound sockets, explicit fallback/require policy, interface/endpoint/subflow observations, API/UI | Negotiated MPTCP, actual additional subflows, plain-TCP fallback and failure behavior on Linux | Native transport, strict/fallback policy and three-subflow failover verified; endpoint administration and WAN aggregation remain open |
| Transport lifecycle | Certificate issuance/renewal/revocation, transactional reload, bounded reconnect and adaptive multipath | Staging CA, expiry/rotation/failure injection, heterogeneous paths | Open |
| Protocol coverage | Individually specified and licensed protocol implementations or managed adapters; consistent ACL/accounting | Independent clients, authentication, TCP/UDP and negative cases per protocol | Six managed protocols accepted with pinned clients and two-host WAN probes; remaining clients/proprietary compatibility stay open |
| Access and resource sharing | Object scopes, resource entitlements, invitation/claim, bounded grants, lease/revocation and bilateral usage reconciliation | Two independent controllers, cross-tenant denial, restart/replay and revocation during traffic | Open |
| Network control | WireGuard membership/routes, NAT/P2P and explicit relay fallback, safe route exclusions | Real gateways and multiple hosts; control access survives reconfiguration | Open |
| Selection and ACL | Cost/capacity/health selection, explainable decisions, GeoIP/ASN and compound policies | Policy fixtures, churn/oscillation, actual routing and default-deny boundaries | Open |
| Operations | Bulk upgrade/replacement, snapshots, migration, log rotation, long history, email/tenant alerts, bounded diagnostics | systemd/OpenRC, recovery in clean state, scoped notification fixtures, fault injection | SMTP/TLS and tenant alert isolation implemented and fixture-tested; other gates remain open |
| Performance and release | Reproducible packages, dependency inventory, small-host profiles, comparative benchmarks | Actual low-memory VM, two hosts, client matrix, 72-hour mixed traffic and accounting reconciliation | Locked dependency/source inventory and workload-specific small-host results available; reproducibility, comparison and 72-hour gates remain open |

The previous passing 0.113.0 evidence is retained. New results must identify the source revision and workload; successful short tests do not replace long-duration acceptance.

## External inputs still needed

- Second independently reachable Linux host: received and inspected (Debian 13.6, x86_64, 1 CPU, 948 MiB RAM, no swap).
- A test domain and authorized DNS/CA staging configuration for certificate and DNS failover tests.
- Supported client versions and any required licensed interoperability targets.
- Actual 1 GiB tier VPS is available; whole-system workload certification is pending. A 512 MiB whole-VM claim still requires that environment.

Local implementation continues while these are pending. Do not mark external or elapsed-time gates complete without their evidence.

## Protocol integration decision

The user authorized maintained open-source protocol engines on 2026-10-29. The panel retains configuration, permissions, accounting, quotas and bandwidth enforcement. Engine source, pinned version and licenses must accompany delivery. Adapter generation alone does not close client interoperability, runtime supervision or accounting acceptance.

## 0.115 development checkpoint

Native MPTCP and tenant-scoped SMTP notifications were committed in 0.114. The current 0.115 work integrates six maintained-engine protocols with native policy/accounting, typed UI, sing-box/mihomo subscription export, source/license distribution and restart/rollback tests. This does not close the remaining workstreams above.

The actual 1 CPU / 948 MiB VPS has been tested with native rules and the optional engine inside the agent's cgroup. The earlier 32 KiB socket-buffer profile intermittently timed out; the 128 KiB profile passed three independent 64-reader rounds. Earlier failures are retained in the evidence, and the UI no longer suggests 32 KiB as a low-memory default. These are workload-specific measurements, not a certified 16 MiB process or 512 MiB VM minimum. Final timings, memory observations and remaining gates are in [RELEASE_0.115.0.md](RELEASE_0.115.0.md).

The full non-payment target specification is also available in English: [NONPAYMENT_TARGETS_EN.md](NONPAYMENT_TARGETS_EN.md). No workstream is marked complete solely because a subset passed.
