# SS forwarding compatibility in 0.119.0

0.119.0 adds optional UDP-over-TCP transport to the native Shadowsocks exit and an optional client build that preserves TCP write-half-close. SS still runs only at the exit. Intermediate VPSs forward the encrypted TCP connection; they need no SS key or external SS engine.

## Use the panel

1. Upgrade the controller and every Agent involved in the path to 0.119.0 before publishing the new field. Older Agents reject unknown configuration fields.
2. Create or edit the **SS exit**. Under **UDP transport compatibility**, choose **Also accept UDP over TCP**. Use TCP or TCP + UDP for the rule and every forwarding hop. TCP + UDP retains ordinary native UDP compatibility.
3. In **Multi-hop topology**, select **Entry client link**. Choose **sing-box / Relay client JSON**. Its server address is the entry VPS; credentials come from the SS exit. With the exit option enabled, the profile contains `udp_over_tcp: {enabled: true, version: 2}`.
4. Save that private JSON as `client.json`. Its local SOCKS listener is `127.0.0.1:1080`; change the port if occupied. Start the supplied compatibility build with `./relay-ss-client run -c client.json` and configure the application to use that SOCKS endpoint.
5. Keep the profile private because it contains the SS key. Stopping the client ends its local listener. Disabling the rule or rotating the SS key revokes access.

A standard `ss://` URI does **not** encode UoT. It remains available for ordinary client compatibility but does not fix a network dropping UDP fragments. Sing-box JSON and mihomo/Clash YAML subscriptions include the negotiated extension when enabled. Formats that cannot represent UoT continue to describe ordinary SS; they do not guarantee this transport.

## Protocol and operational behavior

[SagerNet UoT](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/) is an extension, separate from native SS UDP. This server implements v1 association frames and v2 association/connected frames. The client-facing datagrams travel inside an authenticated, encrypted SS TCP stream; the exit sends normal UDP to their destinations. There is no automatic downgrade to native UDP.

TCP retransmission avoids IP-fragment dependence on the client-to-exit path. Lost TCP segments can delay subsequent datagrams, so native UDP remains useful on networks where it works. The exit-to-destination UDP network must still carry the original datagrams; this feature cannot repair arbitrary destination-side loss.

UoT uses the existing TCP connection limit and TCP active-session counter. Its exit payloads are metered as datagrams, with the same rule/user/node rates, quota, private-address policy, destination ACL and port ACL. Frames and destination tracking are bounded; only previously contacted remote sockets can supply replies. Partial TCP frames survive interleaved UDP replies. Rule cancellation, expiration and idle deadlines close the stream. No extra public management listener is added.

The API field is `inbound_shadowsocks.udp_over_tcp` (boolean, default false). It requires a TCP listener and does not change the stored SS method or password. The native UDP listener still uses the rule's `protocol`. Configurations created before this release preserve their behavior.

## TCP half-close client fix

The pinned upstream sing-box 1.14.4 Shadowsocks AEAD/SS2022 client wrappers do not implement `CloseWrite`. Its copy routine consequently closes the entire encrypted socket when an application's upload ends, losing replies that arrive after FIN. The Relay native forwarding and SS server already preserve their reverse stream.

The optional **Relay SS compatibility client** adds `CloseWrite` to those two client wrappers. It sends a still-pending request header if needed, then half-closes the underlying TCP socket without closing the response reader. It covers the six AEAD/SS2022 ciphers supported by the panel. It is a separately named patched build; it is not an upstream sing-box release and does not modify other clients installed on the user's machine. Other clients need their own correct half-close behavior.

Build it with Go 1.25.5 or later:

```sh
python3 scripts/build_ss_compat_client.py --directory ./relay-client --target linux-amd64
# Or: --target linux-arm64 / --target darwin-arm64
./relay-client/relay-ss-client run -c client.json
```

The build script verifies bundled source and patch hashes, builds from the pinned sing-box source with a local dependency replacement, and preserves source archives and licenses next to the executable. Go dependencies retain `go.sum` verification. The source and exact patch are under `third_party/relay-ss-client/`; upstream sing-box source and license are under `third_party/sing-box/`.

## Acceptance and limits

`python3 scripts/check_ss_uot.py --binary /path/to/relay --client /path/to/relay-ss-client --output results.json` exercises three local forwarding hops, six ciphers, native UDP, UoT v1/v2, normal and delayed-after-FIN TCP replies, destination policies and quota rejection. An optional `--stock-client` records the original half-close failure as a control.

The delivery verification package contains actual local and two-VPS results. Use its verdict and exact client configuration when assessing acceptance. These checks are not a certification of every mobile app, ISP, native-UDP route or hardware minimum.
