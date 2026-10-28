# Managed protocol gateways (development 0.115.0)

The optional gateway adapter connects VLESS (TLS or Reality, with optional Vision), Hysteria2, TUIC v5, AnyTLS, Trojan and VMess to the native rule engine. Protocol wire handling uses **sing-box 1.14.4** as a separate process. It is an upstream component, not an independently written implementation of those protocols.

## Installation and source ownership

`third_party/sing-box/` contains the unmodified corresponding source archive, upstream license notice, GPL v3 text and a pinned checksum manifest. The archive includes upstream `go.mod` and `go.sum`. Go dependency source is resolved during a source build; the archive is not a fully vendored, offline build environment. Upstream licensing and naming/association restrictions remain applicable.

Stage a verified engine package into a new directory:

```sh
python3 scripts/stage_protocol_engine.py --directory ./engine-package --target linux-amd64
```

The command verifies the pinned binary archive and bundled source SHA-256 values. It does not change services. `linux-arm64` and `darwin-arm64` archives are also pinned. To use an already downloaded archive, add `--archive /path/to/archive.tar.gz`. Do not omit source and license files when redistributing the engine.

Install the staged binary at an absolute path readable/executable by the agent, such as `/usr/local/lib/relay-engines/sing-box-1.14.4`, owned by the operator and not writable by group or others. Set `RELAY_PROTOCOL_ENGINE` in the agent environment. Symlink binaries and other engine versions are rejected. The existing deployment installer also accepts agent settings `protocol_engine` and `tls_directory`; these paths remain local operator settings, never controller-supplied executable paths.

To build from the bundled upstream source, use its required Go version (1.25.5 or newer, as stated in `go.mod`), extract the source and run:

```sh
CGO_ENABLED=0 go build -trimpath \
  -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=1.14.4 -s -w -buildid=" \
  -o sing-box ./cmd/sing-box
```

This build command pins the version instead of using the upstream Makefile's latest-tag discovery. Byte-for-byte reproducibility of an upstream release binary has not been established.

## Panel workflow

1. Provision a node-local TLS identity as described in the TLS section of `README.md`, or choose VLESS/Reality and specify a handshake server you are authorized to use.
2. Add a rule and select the protocol in the gateway section. The main listen address is the client-facing address. Generate a UUID/password as appropriate. Reality has a separate private-key generator.
3. Set payload TCP or TCP+UDP, sources, destinations, ports, quota, rate, expiry and connection/session bounds. AnyTLS currently accepts TCP payloads only. Private destinations default to denied. For Reality, allow the camouflage server's address/port in destination policy too; its handshake and fallback bytes consume the same budget.
4. Publish and verify the node's applied revision. Node diagnostics report engine version, running state and automatic restarts.
5. Create a sing-box JSON or mihomo/Clash Meta YAML subscription. For wildcard listeners, supply the public host. Certificate server name can differ from the host clients dial. Client certificate verification stays enabled. Install a private CA or pin its certificate in the client if using privately issued certificates.

Other legacy subscription formats currently skip these gateways with explicit preview reasons. A sing-box export contains outbounds and routing; add the local SOCKS/TUN inlet appropriate for the client application. Client exports contain protocol client credentials and Reality **public** keys, never Reality private keys, local TLS keys or private bridge credentials. Subscription links must be protected as credentials.

## Enforcement and lifecycle

- One shared engine process handles up to 64 enabled gateway rules on a node. No engine process starts for native-only configurations.
- Each gateway routes exclusively to a native, loopback-only SOCKS bridge with a random credential per applied generation. There is no engine direct-egress fallback for authenticated business traffic.
- The gateway applies source CIDR ACLs using the public client address. The native engine applies destination ACLs, private-address policy, rule/owner/tenant/node budgets, aggregate rates, execution gating and durable payload accounting.
- Accounting measures admitted application bytes in each direction, excluding outer TLS/QUIC/protocol framing. **Reality has an explicit exception:** its camouflage handshake/fallback connection also traverses the authenticated native bridge. Its opaque TLS bytes consume the same rule/owner/tenant/node budgets and rates, and destination/private-address restrictions apply. This closes an otherwise unmetered direct-egress path, including unauthenticated fallback traffic. Allow that destination explicitly when using an allowlist.
- Public source ACLs apply when an authenticated protocol connection is routed; they are not a pre-TLS firewall and do not filter Reality's camouflage connection by the original client address. Native connection/session limits apply at the private bridge, including the Reality camouflage dialer. They do not bound all unauthenticated protocol handshakes. Host-level resource caps and ingress protections remain necessary for deployment capacity planning.
- The optional engine receives `GOMEMLIMIT=96MiB` and `GOMAXPROCS=1`. The Go memory value is a GC target, not a hard memory limit. Include the child process in an agent service cgroup when measuring or enforcing memory budgets. QUIC stream concurrency is bounded to the lesser of the rule connection limit and 128 per QUIC connection.
- QUIC servers and sing-box client exports start with a 1,200-byte packet payload, so initial packets fit a 1,280-byte path MTU. Path MTU discovery remains enabled. Other clients control their own initial packet size; do not assume every client's defaults work on constrained tunnel paths.
- Configuration and TLS material are checked before the active process is replaced. A private candidate generation has new bridge credentials. Startup or durable-save failure restores the previous engine generation. Applying a gateway generation briefly restarts the shared engine and interrupts its existing protocol connections; this is not a zero-downtime reload.
- Unexpected engine exits restart with bounded exponential delay. Shutdown stops the owned child. Linux also sets a parent-death signal. Temporary configuration directories use mode 0700 and files use 0600. Crash leftovers can contain secrets and should be handled as private node state.

Changing inbound MPTCP is unsupported on gateway bridges. Native outbound MPTCP remains available when the destination supports it. The UI also preserves health-check settings on ordinary MPTCP relay rules; gateway rules have dynamic destinations and no fixed-target health probe.

## Acceptance scope

`tests/managed_gateways.rs` includes default validation/export checks and explicit engine-dependent tests:

```sh
RELAY_TEST_PROTOCOL_ENGINE=/absolute/path/to/sing-box \
RELAY_TEST_MIHOMO=/absolute/path/to/mihomo \
cargo test --locked --test managed_gateways -- --include-ignored --test-threads=1
```

The pinned acceptance clients are sing-box 1.14.4 and mihomo 1.19.33. Fixtures exercise TCP for all six protocols, UDP for the five enabled for UDP, Reality/Vision, wrong credentials, a wrong Reality key, source/destination/private-address denial, zero quota, expiry, aggregate rate limits, exact payload accounting for certificate-mode protocols, metered Reality camouflage, private bridge authentication, child crash/restart, occupied-public-port rollback and missing-certificate preflight. Plain TLS fallback probes verify that zero quota and a denied camouflage destination cannot bypass the bridge. The mihomo TLS fixtures use an explicit leaf-certificate SHA-256 pin without disabling verification. A fixture-only DIRECT echo probe waits for mihomo forwarding readiness; the protocol transfers themselves are not retried.

These checks do not establish every GUI client's compatibility, WAN capacity, denial-of-service resistance or long-duration reliability. Version-specific execution results and outstanding deployment gates belong in the verification package.
