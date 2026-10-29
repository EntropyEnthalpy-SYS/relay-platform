# UDP compatibility and listener readiness — 0.121.0

Native SS UDP client profiles exported by the panel and sing-box subscriptions now set `udp_fragment: true`. SS encryption adds overhead; disabling fragmentation can prevent a large application datagram from leaving the client on a small-MTU path. TCP-only exports are unchanged, and UoT profiles keep their explicit v2 negotiation.

The optional Relay SS compatibility client now defaults to allowing fragmentation for SS. An explicit `udp_fragment: false` remains authoritative. Its existing TCP write-half-close patch remains in place. All three patches, pinned upstream source archives, checksums and licenses are under `third_party/`; `scripts/build_ss_compat_client.py` builds the version recorded in its manifest. Standard `ss://` URIs cannot carry this setting or negotiate UoT: third-party clients retain their own defaults.

## Early SS2022 response race

The compatibility client now records its request salt before sending the request and synchronizes access from the concurrent reader. Previously, a fast response could arrive while the initial write was still returning, causing a valid response to fail with `bad request salt`. This can terminate an entire UoT association, particularly on a single-CPU host.

`request-salt.patch` includes a deterministic test that holds the request write open while the peer sends a valid response. It covers all three SS2022 methods. The client build runs that test twenty times per method; the verification records the unpatched negative control and a Go race-detector run. This fixes the bundled client; it does not change third-party clients installed independently.

## Listener startup

`reverse-mux-server --ready-file /private/new-run/ready.json` writes a new private JSON file after listener binds and configuration validation succeed. Use `127.0.0.1:0` to let the kernel select a port while keeping it bound. The document reports `control_listen`, `public_listen`, optional `udp_listen` and `metrics_listen`, the process `pid`, the build `version`, and `state: "listeners_bound"`.

Use a fresh pathname for each run. Existing files and symlinks are never overwritten. A consumer must wait for a complete JSON document, verify the PID belongs to the running child and monitor that child for exit. Readiness means listeners have bound; it does not prove a reverse client has authenticated or destination traffic works.

The affected CLI regression fixtures no longer release selected ports before starting the server, start clients before listeners bind, or discard startup diagnostics. Child processes are cleaned up on failure; backend acceptance has a deadline. The byte-limit test also checks that another stream still works after the over-limit stream is reset.

## Reproduce acceptance

Run the ordinary suite with `sh scripts/verify.sh`. Then use the release server binary and newly built compatibility client:

```sh
python3 scripts/check_listener_startup.py --binary /path/to/relay --cycles 30 --output startup.json
sudo python3 scripts/check_ss_udp_mtu.py --binary /path/to/relay --client /path/to/relay-ss-client --output mtu.json
python3 scripts/check_ss_uot.py --binary /path/to/relay --client /path/to/relay-ss-client --output ss-interop.json
```

The MTU probe requires Linux root and `iproute2`. It uses disposable network namespaces and a veth pair at MTU 1280, without changing host routes or firewall rules. It tests native UDP defaults, explicit fragmentation, UoT and an explicit no-fragment negative control. `--previous-client` can additionally demonstrate the prior client default. All positive samples, including the first empty datagram, count; the probe does not retry failed datagrams into passes.

The startup probe includes a deliberately delayed three-second process start, exceeding the former two-second polling window, and verifies listener cleanup for every cycle.

## Reliability boundary

IP fragmentation compatibility fixes a local send constraint. It cannot guarantee that a WAN delivers every UDP datagram. UoT makes the client-to-SS-exit transport reliable; the exit-to-destination UDP leg remains UDP. Arbitrary application datagrams are never blindly retransmitted or duplicated by the relay. WAN acceptance must retain all attempts, inspect both ends and distinguish local drops from network loss. The diagram continues to represent desired routing, with Agent application and real traffic checks kept distinct.

The verification package contains per-VPS regression logs, packet summaries, cold-start/payload tests, startup stress, exact binary hashes and cleanup evidence. These functional checks do not establish minimum hardware or production endurance.
