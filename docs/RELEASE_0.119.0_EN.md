# Relay Platform 0.119.0

Development release, 29 October 2026. The Linux forwarding acceptance passed with the included SS compatibility client and UDP-over-TCP profile. The current macOS WAN path remains partially accepted; see the limitations below.

## Changes

- The rule editor explicitly selects the deployment VPS and service type. Protocol-specific fields follow that selection. The forwarding-path wizard places native forwarding on entry/intermediate nodes and SS on the exit only.
- Entry client exports use the entry address and port with the exit's credentials. Configuration acknowledgment and actual traffic health are presented separately. Template, revision, bulk-edit and shared-dialog behavior is aligned with the API.
- Native SS exits optionally accept SagerNet UoT v1/v2. Datagram framing preserves boundaries and handles interleaved replies without cancelling partial TCP-frame reads. Existing limits, metering, destination policies and lifecycle controls remain in force.
- Native SS UDP now consistently enforces destination ACLs, including domain allowlists after resolution and destination-port restrictions.
- A separately named Relay SS compatibility client, built from pinned sing-box 1.14.4 source, adds `CloseWrite` to the AEAD/SS2022 client wrappers. An application's upload EOF preserves the response direction. The exact dependency source, patch, checksums and licenses are included.
- The panel's **UDP transport compatibility** option and JSON/subscription exports describe UoT explicitly. Ordinary `ss://` links remain native-UDP profiles.

See the [UI audit](UI_FUNCTION_AUDIT_0.118.0_EN.md), [panel tutorial](PANEL_TUTORIAL_EN.md), and [SS client/build guide](SS_COMPATIBILITY_0.119.0_EN.md).

## Verification

| Suite | Result |
| --- | --- |
| macOS default Rust regression | 454 passed, 0 failed; 6 default ignored entries |
| Linux default Rust regression | 454 passed, 0 failed; 8 default ignored entries |
| Deployment tests | 30 passed on each OS |
| Formatting, Clippy, JS syntax, workflows, dialogs and bilingual UI checks | Passed on each OS |
| Optional Linux protocol-engine acceptance | 5 passed |
| Explicit Linux MPTCP acceptance | 2 passed |
| SS interoperability and policy suite | 45 checks passed on each OS |
| Linux public forwarding path across two VPSs | 15 phase checks passed |

Each 45-check SS suite contains one expected-failure stock-client control and 44 functional/policy checks. It covers six ciphers, three local forwarding hops, native UDP, UoT v1/v2, empty through 8,192-byte datagrams, mixed-size bursts, and immediate/delayed-after-FIN TCP responses. The stock-client control reproduces the old failure; it is not a stock-client half-close pass.

The Linux extras explicitly execute seven tests ignored by its default suite. The remaining ignored entry is a crash-worker helper invoked by its parent durability test. The five optional engine tests were not separately run on macOS.

The public-path test used a Linux client on one VPS, the other VPS's public entry listener, the SS exit, and a controlled destination on the entry host. It verified bulk and concurrent TCP, UDP-over-TCP, both half-close cases, the exit's observed source address, wrong-key rejection, direct entry-bypass rejection, exit-stop failure and restart recovery. It did not use three distinct VPSs. Both Agents acknowledged their configurations, and SS was present only on the exit.

The additional Linux UoT matrix delivered 30/30 datagrams; the full path delivered 24/24 plus 5/5 after exit restart. Both nodes reported metered traffic. Temporary services/listeners were removed, firewall rules restored, and all 44 baseline service PIDs preserved.

The locally delivered 917-file tested source ZIP has SHA-256:

`bc1e3629416e6a9b0664e5e0b7244b9357f354154f64596fb6af444fad5309a5`

The GitHub update adds version/release documentation and the smaller CI test-artifact settings to that source snapshot. Application and regression-test code matches the tested snapshot. GitHub CI verifies the committed tree separately. Private VPS state, credentials, client-secret configurations and raw packet captures are not included in the repository.

## Remaining limits

- **macOS WAN half-close remains unaccepted on the current route.** Both half-close probes received zero bytes. Direct plain-TCP controls without Relay or SS reproduced the failure, including one with a one-second delay before FIN. The responsible intermediary or network hop has not been identified.
- The macOS WAN run passed 10/13 top-level checks. UoT delivered 23/24 initial datagrams and 5/5 after restart. The initial lost sample was 1,400 bytes; larger samples passed. Failed samples were retained, not retried into passes.
- The Linux native-UDP comparison delivered 28/30 datagrams, losing one empty and one 512-byte packet. Its half-close checks passed. Native UDP remains subject to network loss; UoT does not make the exit-to-destination UDP segment reliable.
- Use the supplied patched client to reproduce the half-close fix. Arbitrary stock/mobile clients, extra client plugins and optional upstream build tags are not certified by these results.
- The macOS release build completed with a local debug-info stripping warning from `rust-objcopy`; the supplied server binary in the private verification delivery was the Linux release build.
- These checks do not establish minimum hardware, sustained throughput, multi-day endurance, or completion of every platform goal. Payment delivery remains outside the current completion scope.

## Upgrade and reproduce

Upgrade the controller and every participating Agent together before enabling the new configuration field. Preserve each Agent's identity and state; follow [Linux deployment](LINUX_DEPLOYMENT.md).

1. On the SS exit, choose **Also accept UDP over TCP**. Use TCP or TCP + UDP on every forwarding hop.
2. Export **sing-box / Relay client JSON** from **Entry client link**. The resulting local SOCKS listener defaults to `127.0.0.1:1080`.
3. Build the optional client with `python3 scripts/build_ss_compat_client.py --directory ./relay-client --target linux-amd64` (or `darwin-arm64` / `linux-arm64`). Run `./relay-client/relay-ss-client run -c client.json`.
4. Run `sh scripts/verify.sh` with Rust, Node.js, Python and native build dependencies available. CI uses `CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_INCREMENTAL=0` to keep generated test artifacts smaller, as in the successful Linux acceptance rerun.
5. Run `python3 scripts/check_ss_uot.py --binary /path/to/relay --client /path/to/relay-ss-client --output results.json`. Optionally add `--stock-client /path/to/stock-sing-box` for the expected-failure control.

Keep exported client configurations private: they contain working SS credentials. Verify the application's real traffic after configuration acknowledgment.
