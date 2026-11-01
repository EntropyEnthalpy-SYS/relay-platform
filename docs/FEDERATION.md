# Cross-panel sharing (0.140.0, optional feature, off by default)

With `federation` switched on in **Optional features**, a system administrator can give another Relay panel a port range on one of this panel's nodes, and receive ranges that other panels share. The page is **Cross-panel sharing**. Shares and received shares live in metadata (`federation_grant:*`, `federation_remote:*`, `federation_panel_id`), so schema v5 and the recovery log format are unchanged. Agents need nothing new: shared rules are ordinary node rules.

## Owner side

A **share** fixes:

- the node, the listening address (default all addresses) and the address the receiver's users connect to (the node's public IP or host name);
- a port range (at most 1000 ports) and how many rules the receiver may create (1–32, no more than the range has ports);
- the rule kinds: port forwarding to fixed targets and/or Shadowsocks 2022 (`2022-blake3-aes-128-gcm`, key made by the owner);
- optional total bandwidth (at least 1 KiB/s), total traffic (at least 1 MiB) and expiry;
- the source addresses that may connect (required when forwarding is allowed), and destination allow / deny lists. The node itself and private ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `0.0.0.0/8`, `::1`, `fc00::/7`, `fe80::/10`) are denied unless the owner ticks *Allow the node itself and private networks*; that box also decides whether Shadowsocks rules may reach private addresses.

Every share gets a disabled account `share-<first 8 characters of its id>` in the node's tenant (role viewer, random password, nobody signs in as it). It owns the share's rules, so the share's bandwidth is that account's cross-node user rate limit and the traffic limit is a user-scope [budget](BUDGETS.md) named `Share <name>`. Each rule also carries the share's bandwidth, expiry, source list and destination lists, and its meter period is `fed-<share id>`.

The ports must be free: creating or editing a share fails with 409 when another rule or another live share on the node overlaps them (the same address, or either side listening on all addresses). While a share is not revoked, every publish of its node (from the rule editor, templates, maintenance or rollback) drops whatever rules it carries under the share's account and appends the share's own rendering, and refuses with 400 any other rule inside the share's ports. Owners therefore cannot change or remove shared rules except through the share. The per-server rules page shows them with **Manage on Sharing page** instead of edit buttons.

- **Invite code**: one-time, valid 24 hours, `relay-invite:v1:` followed by this panel's address, an invite id and a secret. The address is the browser's `location.origin`, so open the panel at the address other panels will reach (HTTPS; plain HTTP only on loopback). A new code replaces an unused one; once a panel has redeemed the share it cannot be invited again.
- **Edit**: the node cannot change, and a traffic limit can change (not below what is already used or reserved) but cannot be added or removed later. Existing receiver rules must still fit. Changes republish the node.
- **Pause / Resume**: pause publishes the rules disabled and refuses the receiver's rule changes with 409.
- **Revoke**: removes the rules from the node and the account's bandwidth limit, forgets the Shadowsocks keys and makes the receiver's secret fail with 401. The share shows *Node updating* until the node applies the revision without them; from then on the node no longer listens on those ports. A revoked share can only be deleted (its account, budget and traffic history stay).

The panel shows, per share, the traffic its rules have metered (from the node's durable counters), the receiver's last contact, and whether the node runs the newest rules.

## Receiver side

**Enter invite code** sends the code's id and secret plus this panel's id to the owner, which answers with a new 64-hex secret for this panel alone; only that secret is stored (readable by system administrators, never shown). The receiver then:

- sees the share's limits, state, traffic and whether the owner's node applied the newest rules;
- adds or deletes rules: a name, kind, TCP/UDP/both (Shadowsocks needs TCP), a port in the range and, for forwarding, 1–8 targets. The owner checks every request and renders the rule itself; a request outside the share (more rules, another kind, a port outside the range) is refused with 403, and a stale share revision with 409. Shadowsocks rules come back with their key; **Copy link** gives the `ss://` link for clients;
- syncs every minute (and on **Sync now**), confirming the statement it saw to the owner.

## Reconciliation

- Owner counters never go down. When the owner reports less traffic than the highest statement the receiver has seen, the receiver flags *Owner's traffic went down*: the owner probably restored older data. The flag stays until the received share is removed.
- The receiver confirms each statement back. When the confirmed traffic is higher than what the owner now records, the owner's share list shows the same warning.
- When the owner answers 401 the receiver marks the share *Revoked by owner* and stops polling it. Removing a received share only forgets it on the receiver; the rules stay on the owner's node until the owner revokes.

## Protocol

Receivers call the owner's public routes with `Authorization: Bearer <secret>`; see [API.md](API.md#0140-cross-panel-sharing). The receiver pulls and the owner never calls it, so a receiving panel may sit behind NAT. Redirects are not followed and replies over 1 MiB are refused.

## Limits and what is not verified

- 64 shares per panel; IPv4 and IPv6 listening addresses; no key rotation (delete the rule and add it again for a new key).
- Tests cover two panels over HTTP on one machine, an engine forwarding a shared rule and closing it after revoke, widening refusals, pause, statements and both warnings. On the preview panel a share redeemed by the same panel carried real TCP traffic within its bandwidth limit, a sing-box Shadowsocks 2022 client worked through a shared rule, and revoke closed the listeners.
- Not yet verified between two separate real panels over the public internet.
