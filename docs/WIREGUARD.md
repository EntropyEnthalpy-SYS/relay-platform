# WireGuard networking (0.138.0, optional feature, off by default)

NAT traversal between nodes behind NAT was added in 0.139.0; see [below](#nat-traversal-0139-optional-feature-off-by-default).

With `wireguard` switched on in **Optional features**, a system administrator can put nodes and user devices into private WireGuard networks on the **WireGuard networking** page. Networks, members and the public keys that agents report live in metadata (`wg_network:*`, `wg_member:*`, `wg_node_key:*`), so schema v5 and the recovery log format are unchanged.

## Model

- **Network**: a name, a private IPv4 range (/16 to /29 inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10; networks may not overlap), a UDP port (default 51820), an MTU (1280–1420, default 1420), an optional relay node and optional DNS servers for devices (see [Device settings](#device-settings)). The range cannot change while the network has members. Each node uses the link `rwg-` plus the first 8 hex digits of the network id.
- **Node member**: a node whose agent has reported a public key. It gets the lowest free address unless one is given. An optional public endpoint (`host[:port]`, IP or host name) makes it *public*; a node without one is treated as behind NAT. A node can join up to 4 networks, each on its own UDP port (set a per-member port when two networks share one).
- **Device member**: a named device that connects to one public node, its *entry node* (`via`, default: the relay). The panel makes the key pair and returns the wg-quick configuration and a QR code once; only the public key is stored. A device may instead bring its own public key. **New key** replaces the key pair and returns a new configuration once. A device can also have its own allowed IPs and keepalive, be switched off, and have a preshared key (see [Device settings](#device-settings)).
- Limits: 16 networks, 64 members per network.

## Device settings

All are optional; without them a device configuration is exactly what earlier versions wrote.

- **DNS servers** (network `dns`, up to 4 IPv4 or IPv6 addresses): written as `DNS = …` in every device configuration of the network. Nodes are not affected. An edit without `dns` keeps the list; `[]` removes it.
- **Allowed IPs** (device `allowed_ips`, up to 32 ranges such as `10.88.0.0/24`, `192.168.50.0/24` or `0.0.0.0/0`; IPv6 too; a bare address is one host; a range must start at its first address): the device's `AllowedIPs`, which decide what the device sends into the tunnel. Empty means the network's range, as before. This is the device side only: the entry node still accepts only the device's own /32 from it, and Relay does not add NAT or routes on the entry node, so a full tunnel (`0.0.0.0/0`) reaches only what the entry node already forwards to.
- **Keepalive** (device `keepalive`, 0–65535 seconds, 0 for none, default 25): the device's `PersistentKeepalive` towards its entry node.
- **Switch** (device `enabled`, default on): a switched-off device is left out of every node's peers and routes (and does not count for the entry node's forwarding), and the panel shows it as `disabled`. Its public key and preshared key stay, so switching it on again restores the same peers and the device's existing configuration works without changes.
- **Preshared key** (`preshared_key: true` when adding a device, or `{"preshared_key": true|false}` in the body of `POST /api/v1/wireguard/members/{id}/rekey`): the panel makes a random 32-byte key, puts it in the configuration it returns once (`PresharedKey = …` under `[Peer]`), and sends it to the entry node's agent on that node's peer entry for the device. Only the entry node needs it, because a device peers with its entry node only. A rekey without a body keeps the device's choice and makes a new preshared key with the new key pair; an edit cannot add or remove one (400), because the device's configuration would no longer match.
  - Unlike the device's private key, the preshared key must be **stored**, in `wg_psk:<member id>` metadata, so the entry node can be configured after restarts. It is never returned again: views and edit replies show only `preshared_key: true`, and audit entries do not contain it. It is removed with the device or its network.
  - Agents before this change ignore unknown peer fields and would configure the peer without the key, so the device could not connect. Agents now report `preshared_keys: true`; adding a preshared key, or moving such a device to another entry node, is refused (409) until the entry node's agent has reported it. If the entry node later reports without it (for example after a downgrade), the device shows `error` with the reason.

AllowedIPs, keepalive, DNS and the entry node are part of the device's configuration, which the panel cannot show again because it does not keep the private key: after changing them, make a new key (or edit the configuration on the device). The switch and the entry node's peers change without touching the device.

## How members connect

- A pair where at least one node is public connects **directly**; the node behind NAT keeps the path open with a 25 s keepalive.
- A pair where neither node is public goes **through the relay**: the configured relay, or the public node with the lowest address. The relay's own link forwards between its peers. With no public node the pair is **unreachable**, and the panel says so.
- A device reaches every member through its entry node, which forwards on its link.
- Before sending, the controller checks that each /32 appears once per link and every route lies inside the network's range, so a network can never take a default route.

The page lists each member's state (`up`, `updating`, `waiting`, `error` with the agent's reason, `offline`; devices `connected` or `idle`) and every pair's path, relay, newest handshake age and bytes. A relayed pair shows the older handshake of its two legs.

## Sync protocol

- The controller sends `SyncResponse.wireguard` `{enabled, digest, interfaces:[{network_id, name, address, prefix, mtu, listen_port, forwarding, peers:[{public_key, endpoint?, allowed_ips, keepalive?, preshared_key?}]}]}` on every sync. It is empty for non-members and `enabled:false` while the feature is off. Older agents ignore the field; to newer agents, an older controller's missing field means no interfaces. `preshared_key` appears only on an entry node's entry for a device that has one, so states without preshared keys serialize exactly as before.
- The agent returns `EngineStats.wireguard` `{public_key?, ready, probes?, preshared_keys?, problem?, applied, interfaces:[{network_id, name, error?, peers:[{public_key, endpoint?, handshake, rx_bytes, tx_bytes}]}]}` only to a controller that sent the field, because older controllers reject unknown statistics. Controllers ignore unknown fields inside it, so `preshared_keys` is safe for older controllers.

## What the agent does on a server

The agent acts only when its server allows it: `RELAY_WIREGUARD=1`, `CAP_NET_ADMIN` and `wg` from wireguard-tools, all provided by installing [`deploy/relay-agent-wireguard.conf`](../deploy/relay-agent-wireguard.conf) and `apt install wireguard-tools`. Otherwise it reports the missing piece and changes nothing.

- It makes its private key when the feature is on, keeps it in the agent's private state (`agent_wireguard_key`) and passes it to `wg` on standard input only. The status dump's first line, which holds the key, is discarded before parsing; the dump's preshared-key column is never read.
- For each interface: `ip link add … type wireguard`, `wg syncconf` (peers, port), the MTU, `ip -4 address replace` (other addresses on the link are removed), `/proc/sys/net/ipv4/conf/<link>/forwarding` (1 on relays and entry nodes, else 0), link up. It re-applies when the desired state changes and once a minute.
- The `wg syncconf` input has a `PresharedKey` line for every peer: the device's key on an entry node's entry for it, otherwise the all-zero key, which is WireGuard's "no preshared key". `wg syncconf` keeps a key that the input leaves out, so the explicit line is what clears a key a peer had before; for peers without one the kernel state is the same as before.
- It owns only WireGuard links named `rwg-*`. Links with other names, and non-WireGuard links with that prefix, are never touched.
- It refuses a network whose range overlaps an address or route of another link (default routes excepted), or contains the controller's or a peer endpoint's address, and deletes such a link if it already existed. After applying, the route to the controller must not use an `rwg-*` link, or the link is removed.
- It never adds default routes, policy rules, marks, firewall rules or server-wide settings.
- Stopping or upgrading the agent leaves links up, so the network keeps running. Links go away when the panel removes the member or network or switches the feature off, or when the controller revokes the node. After removing the agent itself, delete leftovers with `ip link del rwg-XXXXXXXX`.

## Server preparation (a server administrator's step)

1. `apt install wireguard-tools` (Debian and Ubuntu kernels include the WireGuard module; container VPSes such as OpenVZ/LXC usually cannot create the link and report it).
2. Install the drop-in as `/etc/systemd/system/relay-platform-agent.service.d/wireguard.conf`, then `systemctl daemon-reload && systemctl restart relay-platform-agent`.
3. On public members, open the network's UDP port in the firewall. Hosts whose firewall drops forwarded traffic (for example Docker's `FORWARD DROP` policy) cannot relay or serve devices until that link is allowed.

## Verification and limits

- Unit tests: RFC 7748 key vectors, range and endpoint parsing, direct/relayed/device routing (including an explicit relay that is not the lowest address), digests, overlap guards and status parsing; the default device configuration unchanged byte for byte, DNS, allowed IPs, keepalive and preshared key in a device configuration, the preshared key on the entry node's entry only and never serialized for other peers, `PresharedKey` lines in the `wg` input, a switched-off device leaving every node's peers, routes and the entry node's forwarding and coming back unchanged, and DNS and allowed-IP validation.
- `tests/wireguard.rs`: the switch, roles, key reporting through sync, rendered peers, member states, device keys never stored, endpoint edits, node deletion rules; device settings through sync: network DNS (kept by an edit without it, removed with `[]`), allowed IPs and keepalive in the configuration and kept by edits, device-only fields refused for nodes, a preshared key refused until the entry node's agent reports `preshared_keys`, sent to the entry node only, absent from views and the audit log, an `error` state when the entry node stops reporting support, renewed or dropped by a rekey and removed with the device; a switched-off device leaving the entry node's peers and the other node's routes, and switching on restoring both nodes' desired state with the same digests.
- `sudo python3 scripts/check_linux_wireguard.py --binary target/debug/relay --workdir /tmp/wg-check` (root only, disposable namespaces): one public node, two nodes that reach only the public node, and a device. It checks ping, TCP and UDP separately for direct, relayed and device paths, per-link forwarding with server-wide forwarding left off, unchanged routes outside the links, untouched decoy links, a refused overlapping range, traffic continuing while an agent is stopped, and cleanup.
- The namespace script also adds a second device with network DNS, a preshared key, its own allowed IPs and keepalive. It checks that the preshared key is on the entry node's peer for that device only and that the device connects with it. It also checks that the device cannot reach an address outside its allowed IPs, and that switching the device off removes its peer and switching it on restores it with the same configuration. Device DNS is checked only in the configuration text, because applying it is the device's job (wg-quick).
- Not covered: IPv6 inside networks, exit nodes and subnet routes, real NAT boxes, cloud security groups and WAN path-MTU problems.

## NAT traversal (0.139.0, optional feature, off by default)

With `nat-traversal` switched on (it needs `wireguard` on, and `wireguard` cannot be switched off while it is on), two node members that both lack a public endpoint first try to connect directly instead of through the relay. Devices always connect through their entry node.

**How an attempt works**

1. The relay's own status shows the address and port each node's NAT presents (its WireGuard *endpoint* for that peer). Once the relay has heard both nodes and both have reported recently, the controller starts a *probe*. Only agents from 0.139.0 take part (they report `probes: true`); older agents cannot write a peer entry without allowed IPs, so their pairs stay relayed without attempts.
2. Each node gets a peer entry for the other at that address, with a 25 s keepalive and **no allowed IPs**, while the other's /32 stays on the relay's entry. Setting the keepalive sends a packet at once, so both NATs open a mapping towards each other; WireGuard retries the handshake every 5 s. The entry carries no traffic, so a failed probe costs nothing.
3. When both nodes report a handshake on that entry newer than when the probe began, the pair is **direct**: the /32 moves to the direct entry and off the relay's. The node whose sync made the change gets it at once, and the other node's configuration watch returns (`wireguard_changed`) so it syncs immediately; in the namespace test no ping sent every 50 ms was lost during the switch.
4. No handshake within 45 s: the pair stays **relayed** with the reason *hole punching failed*, and the next probe waits 5 minutes, doubling with each failure up to an hour. A success resets the wait.
5. A direct pair where either side received nothing for 75 s (keepalives normally arrive every 25 s) goes back to the relay with the reason *the direct path received nothing*, and waits the same way. The direct entry follows the relay's view of the peer's address, so a NAT that moves a node to a new port is followed.

**What is kept**: nothing is written to disk. A restarted controller rebuilds each pair from the agents' reports: a pair whose node still has a direct entry with a handshake stays direct, and no pair is decided before both nodes, or one with a working direct entry, have reported, so a restart does not move traffic. Handshake times from an agent are only compared with earlier ones from the same agent, so clock differences between servers do not matter.

**What it needs from the network**: at least one of the two NATs must keep a node's source port for every destination (endpoint-independent mapping, as Linux masquerade and most home routers do). A NAT that picks a new port for each destination (symmetric NAT, common on carrier-grade NAT and some firewalls) cannot be punched; the pair stays on the relay and retries hourly at most. Nothing changes on servers beyond the WireGuard peers on `rwg-*` links: no firewall rules, no port mappings and no server-wide settings.

**In the panel**: the connections table on the WireGuard networking page shows *Direct · through NAT*, *Trying direct · via relay meanwhile*, or *Via relay* with the reason and the minutes until the next attempt.

**Verification**

- Unit tests (`wireguard/punch.rs`): a probe that opens only when both sides handshake, failure after 45 s with a growing wait capped at an hour, a silent direct path falling back, a restart keeping a working direct path and deciding nothing on one report, stale reports ignored, and only endpoint-less node pairs followed. `wireguard.rs` checks the rendered probe and direct entries and the config text without an `AllowedIPs` line (wg refuses an empty one).
- `tests/wireguard.rs`: the switch dependency, probe, direct and relayed entries through real syncs, the watch waking the other node once, the panel's pair paths, and switching off.
- `sudo python3 scripts/check_linux_nat_traversal.py --binary target/debug/relay --workdir /tmp/nat-check` (root only, disposable namespaces with nftables NAT routers that drop unsolicited packets): with the feature off all NAT'd pairs are relayed; switched on, the two nodes behind port-keeping NATs went direct in 7 s with no ping lost, and the relay carried 0 bytes of their TCP and UDP traffic; both pairs with the node behind a random-port NAT fell back after 47 s with the reason and kept working through the relay; a controller restart kept the direct path (48 checks over 25 s); blocking the direct path made the pair fall back after 70 s; cleanup left routes and server-wide forwarding unchanged.
- Not covered: real home routers, carrier-grade NAT, hairpinning behind the same NAT, IPv6, and NAT-PMP/PCP/UPnP mappings for WireGuard ports.
