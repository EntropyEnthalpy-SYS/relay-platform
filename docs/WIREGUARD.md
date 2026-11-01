# WireGuard networking (0.138.0, optional feature, off by default)

With `wireguard` switched on in **Optional features**, a system administrator can put nodes and user devices into private WireGuard networks on the **WireGuard networking** page. Networks, members and the public keys that agents report live in metadata (`wg_network:*`, `wg_member:*`, `wg_node_key:*`), so schema v5 and the recovery log format are unchanged.

## Model

- **Network**: a name, a private IPv4 range (/16 to /29 inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10; networks may not overlap), a UDP port (default 51820), an MTU (1280–1420, default 1420) and an optional relay node. The range cannot change while the network has members. Each node uses the link `rwg-` plus the first 8 hex digits of the network id.
- **Node member**: a node whose agent has reported a public key. It gets the lowest free address unless one is given. An optional public endpoint (`host[:port]`, IP or host name) makes it *public*; a node without one is treated as behind NAT. A node can join up to 4 networks, each on its own UDP port (set a per-member port when two networks share one).
- **Device member**: a named device that connects to one public node, its *entry node* (`via`, default: the relay). The panel makes the key pair and returns the wg-quick configuration and a QR code once; only the public key is stored. A device may instead bring its own public key. **New key** replaces the key pair and returns a new configuration once.
- Limits: 16 networks, 64 members per network.

## How members connect

- A pair where at least one node is public connects **directly**; the node behind NAT keeps the path open with a 25 s keepalive.
- A pair where neither node is public goes **through the relay**: the configured relay, or the public node with the lowest address. The relay's own link forwards between its peers. With no public node the pair is **unreachable**, and the panel says so.
- A device reaches every member through its entry node, which forwards on its link.
- Before sending, the controller checks that each /32 appears once per link and every route lies inside the network's range, so a network can never take a default route.

The page lists each member's state (`up`, `updating`, `waiting`, `error` with the agent's reason, `offline`; devices `connected` or `idle`) and every pair's path, relay, newest handshake age and bytes. A relayed pair shows the older handshake of its two legs.

## Sync protocol

- The controller sends `SyncResponse.wireguard` `{enabled, digest, interfaces:[{network_id, name, address, prefix, mtu, listen_port, forwarding, peers:[{public_key, endpoint?, allowed_ips, keepalive?}]}]}` on every sync. It is empty for non-members and `enabled:false` while the feature is off. Older agents ignore the field; to newer agents, an older controller's missing field means no interfaces.
- The agent returns `EngineStats.wireguard` `{public_key?, ready, problem?, applied, interfaces:[{network_id, name, error?, peers:[{public_key, endpoint?, handshake, rx_bytes, tx_bytes}]}]}` only to a controller that sent the field, because older controllers reject unknown statistics.

## What the agent does on a server

The agent acts only when its server allows it: `RELAY_WIREGUARD=1`, `CAP_NET_ADMIN` and `wg` from wireguard-tools, all provided by installing [`deploy/relay-agent-wireguard.conf`](../deploy/relay-agent-wireguard.conf) and `apt install wireguard-tools`. Otherwise it reports the missing piece and changes nothing.

- It makes its private key when the feature is on, keeps it in the agent's private state (`agent_wireguard_key`) and passes it to `wg` on standard input only. The status dump's first line, which holds the key, is discarded before parsing.
- For each interface: `ip link add … type wireguard`, `wg syncconf` (peers, port), the MTU, `ip -4 address replace` (other addresses on the link are removed), `/proc/sys/net/ipv4/conf/<link>/forwarding` (1 on relays and entry nodes, else 0), link up. It re-applies when the desired state changes and once a minute.
- It owns only WireGuard links named `rwg-*`. Links with other names, and non-WireGuard links with that prefix, are never touched.
- It refuses a network whose range overlaps an address or route of another link (default routes excepted), or contains the controller's or a peer endpoint's address, and deletes such a link if it already existed. After applying, the route to the controller must not use an `rwg-*` link, or the link is removed.
- It never adds default routes, policy rules, marks, firewall rules or server-wide settings.
- Stopping or upgrading the agent leaves links up, so the network keeps running. Links go away when the panel removes the member or network or switches the feature off, or when the controller revokes the node. After removing the agent itself, delete leftovers with `ip link del rwg-XXXXXXXX`.

## Server preparation (a server administrator's step)

1. `apt install wireguard-tools` (Debian and Ubuntu kernels include the WireGuard module; container VPSes such as OpenVZ/LXC usually cannot create the link and report it).
2. Install the drop-in as `/etc/systemd/system/relay-platform-agent.service.d/wireguard.conf`, then `systemctl daemon-reload && systemctl restart relay-platform-agent`.
3. On public members, open the network's UDP port in the firewall. Hosts whose firewall drops forwarded traffic (for example Docker's `FORWARD DROP` policy) cannot relay or serve devices until that link is allowed.

## Verification and limits

- Unit tests: RFC 7748 key vectors, range and endpoint parsing, direct/relayed/device routing (including an explicit relay that is not the lowest address), digests, overlap guards and status parsing.
- `tests/wireguard.rs`: the switch, roles, key reporting through sync, rendered peers, member states, device keys never stored, endpoint edits, node deletion rules.
- `sudo python3 scripts/check_linux_wireguard.py --binary target/debug/relay --workdir /tmp/wg-check` (root only, disposable namespaces): one public node, two nodes that reach only the public node, and a device. It checks ping, TCP and UDP separately for direct, relayed and device paths, per-link forwarding with server-wide forwarding left off, unchanged routes outside the links, untouched decoy links, a refused overlapping range, traffic continuing while an agent is stopped, and cleanup.
- Not covered: hole punching (direct connections between two nodes behind NAT are the next feature, `nat-traversal`), IPv6 inside networks, exit nodes and subnet routes, real NAT boxes, cloud security groups and WAN path-MTU problems.
