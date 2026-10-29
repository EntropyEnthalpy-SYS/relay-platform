# Relay panel tutorial — adding VPS nodes and forwarding traffic

Applies to the 0.125.0 source release. Node enrollment, rule placement, the Agent CLI and deployment commands were reviewed on 2026-10-29. For SS client configuration and remaining WAN limits, read the [0.121.0 UDP and listener-readiness notes](RELEASE_0.121.0_EN.md) and [SS compatibility guide](SS_COMPATIBILITY_0.119.0_EN.md). Check each installed Agent's version before upgrading.

Use **Templates / 模板库** to start a common setup. **Node rules / 节点规则** manages one VPS's listeners and services. **Forwarding paths / 转发路径** groups those rules into complete entry-to-destination diagrams; it is another view of the same configuration. Creating a multi-hop path creates one rule on each participating VPS.

Open **Overview → Monitoring** for the large charts, forwarding graph, event list and node resource table. **Workspace** uses the compact layout. The theme button independently selects light or dark colors. Empty metrics on example nodes mean there are no Agent reports; they are not live VPS measurements. See the [monitoring guide](RELEASE_0.125.0_EN.md).

The library includes four built-in templates: single-VPS port forwarding, single-VPS Shadowsocks, multi-hop port forwarding, and multi-hop Shadowsocks. **My saved rule templates** contains configurations you saved yourself; it can be empty while the four built-ins remain available. All four built-ins use the same guided form: choose VPSs, accept automatic addresses and ports, then click **Preview changes**. Manual ports and source limits are under **Advanced**. Nothing is published until you explicitly choose **Publish these changes**. Click any VPS card in the draft diagram to edit that hop below the diagram. The selected exit also exposes destination or SS settings. **Done editing this hop** keeps your changes. Clicking a card during review returns to the draft; preview it again before publishing. On the saved path page, click a VPS card to open its exact node rule. See the [diagram editing guide](RELEASE_0.124.0_EN.md) and [workflow guide](RELEASE_0.123.0_EN.md) and [diagram guide](FORWARDING_DIAGRAM_0.120.0_EN.md).

## 1. Understand the three roles

- **Controller / panel:** the web interface, accounts, desired configurations, and usage records.
- **Agent / node:** the process on each forwarding VPS that opens ports and forwards traffic.
- **Destination:** the application or next relay that receives the forwarded connection.

```text
Browser -------------------- HTTPS --------------------> Controller
Forwarding VPS / Agent ----- HTTPS enrollment + sync ---> Controller

Client ----> Forwarding VPS / Agent ----> Destination application
```

Normal forwarded traffic travels through the Agent. A controller also carries forwarding traffic only when you run an Agent there and select its rules. A destination running an ordinary application does not need a Relay Agent; it needs one if you want to manage it as another relay hop.

The panel registers nodes and supplies an enrollment command. Agent installation is performed on the VPS; there is no panel-driven SSH installer in this version.

## 2. Prepare the controller and installation files

Before enrolling a remote VPS, have:

1. A running, compatible controller and an administrator or tenant-administrator account.
2. A working HTTPS controller URL, such as `https://panel.example.com`, whose certificate the Agent trusts. A remote Agent rejects ordinary HTTP. A private CA can be supplied with the installer's `--ca-certificate` option.
3. A Linux release bundle for the VPS architecture, its trusted signing public key, and the deployment scripts. Appendix A shows how to build these from the public repository.
4. A new Agent installation on a Linux VPS using systemd, Python 3.9 or newer, OpenSSL, and CA certificates. The commands below use a root Bash shell on Debian/Ubuntu.

The repository currently provides source and a version tag. The initial GitHub CI workflow verifies a Linux build but does not publish downloadable Linux binaries. Build the bundle using Appendix A before proceeding if you do not already have one.

Use the deployment tool for service installation; it generates the Agent's Linux permissions, including `AF_NETLINK` for local interface detection. Its managed service is named `relay-platform-agent.service` and its state directory is `/var/lib/relay-platform/agent`.

These are **new-node instructions**. If an Agent is already installed, retain its identity and use the upgrade procedure in [LINUX_DEPLOYMENT.md](LINUX_DEPLOYMENT.md). The installer supports one managed Agent role per VPS. Do not overwrite an existing Agent's database or reuse one node identity on multiple VPSs.

## 3. Register the VPS in the panel

1. Sign in and use **English / 中文** to select your interface language.
2. Open **Nodes / 节点管理**.
3. Click **+ Enroll node / + 注册节点**.
4. Enter a useful name, such as `Singapore-entry-01`. Type, group, and tags are inventory labels; they do not configure routes.
5. Under **Connection defaults for new rules**, enter the VPS's reachable IP or hostname without a port. This is saved once and reused. The default automatic port range is 20000–29999; open **Port range / NAT / listen IP** to change it. NAT requires a continuous range already mapped by your provider.
6. Select the runtime protection policy.
7. Click **Create node / 创建节点** and save the **node ID** and **one-time enrollment token** from the resulting dialog.

| Policy | Behavior and trade-off |
| --- | --- |
| Availability first — UI default | Continues using the last configuration during controller outages. Suitable for learning the basic forwarding workflow. It cannot strictly enforce shared budgets while disconnected and does not support node pause/expiry. |
| Strict lease | Stops forwarding if the control lease cannot be renewed. Use when execution ownership, pause/expiry, or stricter quota enforcement is required. A controller outage can interrupt forwarding. |

The policy is fixed at node creation. The enrollment token is displayed once. Save it privately before closing the dialog; the panel does not need your SSH password.

## 4. Install and start the Agent

Use a root Bash shell on the new VPS. In this example, `/root/relay-onboarding-0.125.0` already contains:

```text
relay-linux-0.125.0.tar.gz
signing-public.pem
scripts/relay_deploy.py
scripts/deployment/...
```

Install the runtime tooling if necessary:

```sh
apt-get update
apt-get install --yes python3 openssl ca-certificates curl
cd /root/relay-onboarding-0.125.0
umask 077
```

Capture the token without placing its actual value in a command saved to shell history:

```bash
read -r -s -p 'Paste the one-time node enrollment token: ' relay_enrollment_token
printf '\n'
printf '%s\n' "$relay_enrollment_token" > enrollment.secret
unset relay_enrollment_token
chmod 600 enrollment.secret
```

Create `agent.json`, replacing both example values with the controller URL and node ID from the panel:

```json
{
  "controller": "https://panel.example.com",
  "node_id": "REPLACE_WITH_NODE_ID",
  "poll_seconds": 5
}
```

Then verify, inspect, install, start, and enable the service:

```sh
python3 scripts/relay_deploy.py verify \
  --bundle relay-linux-0.125.0.tar.gz \
  --trusted-key signing-public.pem

python3 scripts/relay_deploy.py preflight \
  --role agent --config agent.json \
  --bundle relay-linux-0.125.0.tar.gz \
  --trusted-key signing-public.pem
```

Continue only after preflight reports `ready: true`. Resolve any reported error first.

```sh
python3 scripts/relay_deploy.py install \
  --role agent --config agent.json \
  --bundle relay-linux-0.125.0.tar.gz \
  --trusted-key signing-public.pem \
  --enrollment-token-file enrollment.secret

python3 scripts/relay_deploy.py start --role agent
python3 scripts/relay_deploy.py enable --role agent

systemctl status relay-platform-agent --no-pager
journalctl -u relay-platform-agent -n 50 --no-pager
```

For a private controller CA, add `--ca-certificate /absolute/path/controller-ca.pem` to the `install` command. This file contains the CA certificate, not its private key.

Return to **Nodes** and wait for control connectivity and an applied configuration revision. An active systemd service alone does not prove successful enrollment or forwarding. After initial enrollment, the Agent keeps its identity in its private state; ordinary restarts do not require a new node or token.

## 5. Create a first forwarding test on one VPS

This test needs only the newly enrolled VPS and your computer. It forwards a public high port to a small local HTTP service:

```text
Your computer --> ENTRY_VPS_IP:18081 --> 127.0.0.1:18080 on that VPS
```

On the forwarding VPS, start a temporary test website in a dedicated directory:

```sh
relay_demo_dir=$(mktemp -d /tmp/relay-demo.XXXXXX)
printf 'relay-forwarding-ok\n' > "$relay_demo_dir/index.html"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$relay_demo_dir"
```

Keep this terminal open during the test. In the panel, open **Templates / 模板库**, find **Single-VPS port forwarding / 单 VPS 端口转发**, and click **Use this template / 使用此模板**. You can also start from **Node rules → + Add rule**.

| Field | Value for this test |
| --- | --- |
| Path name | `HTTP-forward-test` |
| Exit service | Forward to fixed targets |
| Service VPS | Select the newly enrolled VPS |
| Destination | `127.0.0.1:18080` |
| Advanced: protocol, owner and tunnels | Select TCP for this HTTP-only example |

The reachable address is reused from the node's connection defaults. The panel suggests a port that is unused by saved rules in that range. If the address is missing, fill **Reachable VPS address** on the VPS card once and click **Save VPS address and allocate ports**. A node name or the controller's hostname is never used as a guessed VPS address.

For the exact `18081` port used by the commands below, open the VPS card's **Advanced: ports, source limits and VPS address**, check **Set addresses and ports manually for this path**, and enter `0.0.0.0:18081` for the listener and `ENTRY_VPS_IP:18081` for the reachable endpoint. Otherwise keep automatic allocation and substitute the displayed port in those commands.

You can restrict this demo to your computer's public IPv4 address using `YOUR_PUBLIC_IP/32` in **Allowed source CIDRs**. A blank list permits all sources not explicitly denied.

Click **Preview changes / 预览发布内容**. Check the selected VPS, its proposed endpoint, and `127.0.0.1:18080` as the final target. Then click **Publish these changes / 发布这些变更**. On **Forwarding paths**, confirm the Agent is connected, its desired and applied revisions match, and there is no application error.

Previewing does not reserve ports. Publication checks configuration revisions and graph conflicts. An unrelated process can still occupy a proposed port; the Agent's application result confirms whether the listener opened. The panel does not alter firewall rules or provider NAT mappings.

## 6. Open the port and verify the actual path

Allow inbound **TCP 18081** in both the VPS provider's security group and the host firewall, preferably from your test computer's public IP for this demo. The panel does not create these firewall rules. The local target at `127.0.0.1:18080` does not need a public firewall opening.

The Agent needs outbound HTTPS access to the controller. Forwarding also needs outbound access to the destination. SSH access is for your installation and maintenance work.

From another terminal on the forwarding VPS:

```sh
curl --fail --max-time 5 http://127.0.0.1:18080/
ss -lntp 'sport = :18081'
```

From your own computer, replace `ENTRY_VPS_IP` with the VPS's real reachable IP:

```sh
curl --fail --max-time 10 http://ENTRY_VPS_IP:18081/
```

Expected output: `relay-forwarding-ok`. Check the panel's usage and diagnostics for the corresponding rule; a short request may finish before a live connections widget refreshes. Traffic in both directions contributes to the rule's usage.

After the demo, disable the rule and stop the temporary HTTP server with Ctrl+C. To keep a real application available, manage that application as a persistent service as well as the Agent.

## 7. Forward to an application on another VPS

Suppose the destination application is reachable as `TARGET_VPS_IP:8080`. It can be an ordinary web server; a Relay Agent is not required on that destination.

First test the destination **from the forwarding VPS**:

```sh
curl --fail --max-time 5 http://TARGET_VPS_IP:8080/
```

If this fails, fix the destination's service bind address, routing, and firewall before changing the forwarding rule. `127.0.0.1` refers to the machine running the Agent, not another VPS. A service on the second VPS bound only to its own loopback address is not directly reachable from the first VPS.

Rules created by the guide have a declared reachable endpoint. Before changing their route, disable the affected path and wait for its Agents to apply the stop and for all active sessions to reach zero. Then edit the target to `TARGET_VPS_IP:8080`, preserve the listener, review the change, and publish. Re-enable the path, wait for matching revisions, and repeat the request to `http://ENTRY_VPS_IP:18081/`.

Always test the new route with a new connection after the stopped edit and re-enable sequence. Forwarding preserves the application's bytes, including HTTP Host headers and TLS handshakes; it does not automatically rewrite hostnames or create matching certificates.

## 8. Other common configurations

| Use case | Listener | Destination | Protocol and notes |
| --- | --- | --- | --- |
| Existing HTTPS service | `0.0.0.0:1443` | `ORIGIN_IP:443` | TCP; leave Relay TLS profiles unset for end-to-end TLS pass-through. The client still needs the original certificate hostname. |
| UDP application | `0.0.0.0:25000` | `TARGET_VPS_IP:25000` | UDP; allow UDP in both firewalls and test with the application's real client. A TCP connection test proves nothing about UDP delivery. |
| Service using TCP and UDP | `0.0.0.0:25000` | `TARGET_VPS_IP:25000` | TCP + UDP; allow and test both transports independently. |
| Several interchangeable backends | One listener | Multiple target rows | These are candidate destinations for load balancing, not a sequence of relay hops. |

For two relay hops, enroll both Agents, then choose **Templates → Multi-hop port forwarding** or **Forwarding paths → Create forwarding path**:

```text
Client --> Agent A --> Agent B --> Destination
```

Choose A as the entry and B as the exit. Addresses and ports fill automatically from saved node defaults or an unambiguous existing rule. Set the final destination, review the diagram, and publish. The wizard creates both rules and their next-hop reference together. **+ Add relay VPS (optional)** inserts a VPS before the selected exit. Only relays have move/remove controls. Selecting a VPS already in the path swaps the two positions, so even a two-VPS path can exchange entry and exit. A wildcard address such as `0.0.0.0` cannot be a reachable remote endpoint. Both nodes must apply their configurations, and the inter-node port must be reachable.

For `Client → A → B → C (SS) → Internet`, choose **Multi-hop Shadowsocks**, select A as entry and C as exit, then add B as a relay. Addresses and ports are automatic. An SS 2022 AES-256-GCM key is generated; expand the SS section only to change its settings. Only C receives an SS service; A and B forward encrypted traffic. After publishing, use **Entry client link** on the path card. The link uses A's reachable address and C's SS credentials. The SS service is built into the Agent. Managed protocols such as VLESS or Hysteria2 still require their supported engine on the service VPS.

To reuse rules that already exist, edit A's target and choose **Existing next-hop rule (optional)**. The downstream rule must have a reachable address. See [TOPOLOGY.md](TOPOLOGY.md) for the preview, publish, and stop-before-rerouting workflow.

Each hop maintains its own metering. Do not assume that a multi-hop path is counted only once against a shared budget.

## 9. Limits and everyday operation

- **Quota:** the rule editor uses bytes. Blank means unlimited; `0` blocks payload.
- **Rule rate:** bytes per second, combined upload and download. For example, `12500000` bytes/s corresponds to 100 Mbit/s combined. This setting is distinct from the node-wide rate dialog, which uses Mbit/s.
- **Source ACL:** deny entries take priority. A nonempty allow list admits only matching source networks.
- **Port choice:** start above 1024. The installed Agent runs as a dedicated non-root user and the installer does not grant low-port capabilities.
- **IPv6:** `[::]:PORT` is IPv6-only in this implementation. Create a separate IPv4 listener if you need both families.
- **Reboot persistence:** the enabled systemd service restarts the Agent. Keep its original state directory and node identity.
- **Saved templates:** after a rule works, use **Save as template** in Node rules. It appears below the built-ins in Templates. **Use this template** asks for the destination VPS, a new name, listener and reachable address, then previews the change. It preserves targets and policies while creating a fresh rule identity and metering period.
- **Upgrades:** back up state, upgrade the controller before Agents, and follow [LINUX_DEPLOYMENT.md](LINUX_DEPLOYMENT.md). Updating source on GitHub does not itself deploy a binary to a VPS.

## 10. Troubleshooting

| Symptom | First checks |
| --- | --- |
| Node remains awaiting enrollment | Service log; correct node ID/token; HTTPS controller reachability; certificate trust; token-file permissions. |
| Service is active but node is offline | Agent logs, DNS resolution, outbound HTTPS, clock and certificate validity, and whether credentials were revoked. |
| Desired revision differs from applied | Read the application error; check occupied ports, unavailable local bind addresses, missing TLS profiles, or unsupported configuration. |
| Node online but client times out | Provider firewall, host firewall, actual Agent listener, source ACL, destination reachability from that VPS, quota and expiry. |
| Address already in use | Use `ss -lntp` or `ss -lnup` to identify the existing listener; choose an unused port. |
| Works locally but not from another machine | Loopback-only listener, firewall, source ACL, incorrect public IP, or missing provider/NAT port mapping. |
| HTTPS certificate or website mismatch | Check the client hostname/SNI and Host header. Raw TCP forwarding does not replace certificates or rewrite HTTP. |
| Forwarding stops during a controller outage | Check whether the node uses a strict lease. |
| UDP appears healthy but no replies arrive | Use the real UDP application or an echo test; inspect both directions and both firewalls. UDP has no TCP-style connection handshake. |

Useful commands on the Agent VPS:

```sh
systemctl status relay-platform-agent --no-pager
journalctl -u relay-platform-agent -n 100 --no-pager
ss -lntp
ss -lnup
```

## Appendix A — build and distribute a Linux bundle

Build on Linux with the target VPS's CPU architecture and compatible system libraries. A larger matching Linux build machine can prepare the bundle for a small VPS. The build machine and runtime VPS do not need to be the same machine; compilation resources are not a measured minimum runtime requirement.

The following uses a root Bash shell on a Debian/Ubuntu build machine and a fresh source directory:

```sh
apt-get update
apt-get install --yes git curl ca-certificates build-essential pkg-config clang libclang-dev openssl python3

git clone --branch v0.125.0 --depth 1 \
  https://github.com/EntropyEnthalpy-SYS/relay-platform.git \
  /root/relay-build-0.125.0
cd /root/relay-build-0.125.0
```

If Rustup is absent, install it using the [official Rust installation instructions](https://rust-lang.org/tools/install/), then open a new shell or load its environment. Select the same Rust version used by project CI and build:

```sh
. "$HOME/.cargo/env"
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 build --locked --release --bin relay --jobs 2
./target/release/relay build-info

install -d -m 700 /root/relay-release-0.125.0
python3 scripts/relay_deploy.py keygen \
  --directory /root/relay-release-0.125.0/signing

python3 scripts/relay_deploy.py pack \
  --binary target/release/relay \
  --signing-key /root/relay-release-0.125.0/signing/signing-private.pem \
  --source-revision "$(git rev-parse HEAD)" \
  --output /root/relay-release-0.125.0/relay-linux-0.125.0.tar.gz
```

The signing directory is created once for this example; retain its private key privately for release management. The private key is not needed on the Agent VPS.

From the build machine, replace `ENTRY_VPS_IP` and copy only the bundle, public key, and scripts over your trusted SSH connection:

```sh
ssh root@ENTRY_VPS_IP 'install -d -m 700 /root/relay-onboarding-0.125.0'

scp /root/relay-release-0.125.0/relay-linux-0.125.0.tar.gz \
  /root/relay-release-0.125.0/signing/signing-public.pem \
  root@ENTRY_VPS_IP:/root/relay-onboarding-0.125.0/

scp -r /root/relay-build-0.125.0/scripts \
  root@ENTRY_VPS_IP:/root/relay-onboarding-0.125.0/
```

If building on the Agent VPS itself, use ordinary local copies of the same three items into the onboarding directory instead of SCP. Then continue with enrollment and installation above.

## Related guidance

- [UI and embedded handbook](UI_WORKSPACE_EN.md)
- [Linux deployment, upgrades, and rollback](LINUX_DEPLOYMENT.md)
- [Port ranges, DNS, and outbound binding](ROUTING.md)
- [Multi-hop topology](TOPOLOGY.md)
- [GitHub updates and release workflow](GITHUB_WORKFLOW_EN.md)
- [Current non-payment delivery status](NONPAYMENT_DELIVERY.md)

The automatic regression suite and this basic tutorial do not replace the separate real-client, optional-engine, WAN, endurance, and minimum-hardware acceptance work.
