# Relay documentation

Relay is a self-hosted platform for people who run forwarding and relay servers. A web panel keeps your servers, forwarding rules, users and usage records. A small agent on each server opens the ports and carries the traffic, and your customers' apps connect to those servers directly. This page explains what Relay is, how to install it, how to use each feature in the panel, how to handle common deployments, and where to look when something goes wrong. It describes Relay 0.151.0. Relay is still a development release. Read [Current limits](#current-limits) before you depend on it.

## Contents

- [Overview](#overview)
  - [What Relay is](#what-relay-is) · [The three roles](#the-three-roles) · [What makes Relay different](#what-makes-relay-different) · [Finding your way around the panel](#finding-your-way-around-the-panel)
- [Getting started](#getting-started)
  - [Requirements](#requirements) · [1. Build and sign a package](#1-build-and-sign-a-package) · [2. Install the panel](#2-install-the-panel) · [3. Add HTTPS](#3-add-https) · [4. Sign in](#4-sign-in) · [5. Add your first server](#5-add-your-first-server) · [6. Create your first forwarding](#6-create-your-first-forwarding) · [7. Check that it works](#7-check-that-it-works)
- [Core features](#core-features)
  - [Servers and their settings](#servers-and-their-settings)
  - [Forwarding](#forwarding)
  - [Proxy services and protocols](#proxy-services-and-protocols)
  - [Client subscriptions](#client-subscriptions)
  - [Traffic quotas, budgets and speed limits](#traffic-quotas-budgets-and-speed-limits)
  - [Access control](#access-control)
  - [DNS, DDNS and the authoritative DNS pool](#dns-ddns-and-the-authoritative-dns-pool)
  - [WireGuard networking and NAT traversal](#wireguard-networking-and-nat-traversal)
  - [Reverse tunnels and router port mapping](#reverse-tunnels-and-router-port-mapping)
  - [Cross-panel sharing](#cross-panel-sharing)
  - [Users, tenants, roles, two-step verification and API tokens](#users-tenants-roles-two-step-verification-and-api-tokens)
  - [Wallet, plans, orders, discount codes and gift codes](#wallet-plans-orders-discount-codes-and-gift-codes)
  - [Support tickets and announcements](#support-tickets-and-announcements)
  - [Templates and batch publishing](#templates-and-batch-publishing)
  - [Optional features](#optional-features)
- [Scenarios](#scenarios)
  - [One entry, many exits](#one-entry-many-exits)
  - [Servers that cannot reach the panel (mainland China, IX lines)](#servers-that-cannot-reach-the-panel-mainland-china-ix-lines)
  - [Private-line mappings: the public port differs from the bound port](#private-line-mappings-the-public-port-differs-from-the-bound-port)
  - [Servers behind home routers or NAT](#servers-behind-home-routers-or-nat)
- [Help](#help)
  - [Monitoring](#monitoring) · [Alerts](#alerts) · [Live logs and the diagnostic report](#live-logs-and-the-diagnostic-report) · [Upgrades and rollback](#upgrades-and-rollback) · [Backup and restore](#backup-and-restore) · [FAQ](#faq) · [Current limits](#current-limits) · [Further reading](#further-reading)

---

## Overview

### What Relay is

Relay forwards TCP and UDP traffic through one or more of your servers. It can also run proxy services on them: Shadowsocks, SOCKS5, HTTP CONNECT and HTTP/2 CONNECT are built in, and VLESS (with TLS or Reality), Hysteria2, TUIC, AnyTLS, Trojan and VMess run through an optional engine. Around the forwarding it adds metering, quotas, speed limits, access control, health checks, client subscriptions, DNS automation, private WireGuard networks and a simple billing layer.

Relay was written from its own source. It needs no commercial product or activation to run.

### The three roles

```text
Browser ------------------ HTTPS ------------------> Panel (controller)
Server running an agent -- HTTPS enrollment + sync -> Panel

Client app --> Entry server --> (relay servers) --> Exit server --> Destination
               agent            agent               agent
```

| Role | What it does |
| --- | --- |
| **Panel** (controller) | The web interface and API. It stores users, servers, the desired configuration of every server, and usage history. It carries no customer traffic unless you also run an agent on the same machine. |
| **Agent** | One per forwarding server. It connects out to the panel over HTTPS, receives its configuration, opens the listening ports, forwards traffic and reports usage, health and logs. |
| **Clients** | Your customers' apps, or an upstream server, connecting to an agent's port. The final destination (a website or your own service) needs no Relay software. |

The panel registers servers and gives you the commands to run, but it never logs in to your servers over SSH. You install the agent yourself.

### What makes Relay different

- **Signed, offline installation.** You build the program once, sign it with your own key and copy one package to each server. Each server checks the signature against your public key before installing, so a damaged or altered package is refused. Nothing is downloaded during installation, and earlier versions are kept for rollback.
- **Private keys stay on the servers.** TLS private keys for forwarding live in each agent's private state directory, and the panel only refers to them by name. Each agent creates its own WireGuard key on its server. The panel stores node credentials, API tokens and subscription tokens only as hashes, and shows the tokens you need once. Proxy keys and passwords (Shadowsocks keys, Reality keys and so on) are part of a rule's configuration, so the panel does store those.
- **Per-hop accounting.** Every rule on every server keeps its own durable ledger, and traffic is recorded on disk before it is forwarded. On a path through three servers, each hop counts what it carried. The panel also shows the success rate of real connections at each hop, so you can see where a path breaks.
- **Nothing changes until a server confirms it.** Every change is a numbered revision. The panel shows the desired and the applied revision of each server. If a server cannot open a port, it keeps running its previous configuration and reports why.
- **Your firewall stays yours.** The installer and the agent never change firewall rules, default routes or system-wide settings. Features that need extra permissions (port 53, WireGuard, MPTCP extra paths) only work after you install their permission file on the server.

### Finding your way around the panel

The sidebar groups the pages by task:

| Group | Pages |
| --- | --- |
| **Overview** | **Overview** |
| **Forwarding setup** | **Nodes**, **Forwarding rules** (tabs **All forwarding** and **By server**), **WireGuard networking**, **Cross-panel sharing**, **Rule templates** |
| **Monitoring & usage** | **Target health**, **Traffic ledger**, **Shared budgets**, **Live logs**, **Diagnostics**, **Alerts & notifications** |
| **Customers & services** | **Client subscriptions**, **DNS management**, **Announcements**, **Support tickets**, **Wallet & orders** |
| **System & help** | **Users & permissions**, **Account security**, **Audit log**, **Recovery protection**, **Optional features**, **Feature status**, **Handbook** |

**DNS management**, **WireGuard networking**, **Cross-panel sharing**, **Live logs**, **Diagnostics**, **Audit log**, **Recovery protection** and **Optional features** are for system administrators only. Viewers do not see **Alerts & notifications** or **Rule templates**.

Press Ctrl+K (Command+K on a Mac) to search pages and handbook articles. **English / 中文** switches the language without signing you out. **Appearance** chooses a dark, light or system theme and an accent color; it affects only your own browser. The **Handbook** page has short built-in guides, and the page guide button on each page opens the relevant one.

---

## Getting started

This is the short path from empty servers to a working forwarding. The [Deployment guide](DEPLOYMENT_GUIDE_EN.md) has the same steps with more detail and an nginx alternative.

### Requirements

- **A panel server:** Debian 12/13 or Ubuntu 24.04 on x86_64 or ARM64, with systemd and root access. The panel needs few resources.
- **A domain name for the panel,** such as `panel.example.com`, with an `A` record (and `AAAA` for IPv6) pointing at the panel server. Agents on other servers only connect to a panel over HTTPS, so you need this as soon as you add a remote server.
- **One or more forwarding servers** with the same operating system requirements, plus Python 3.9 or newer, OpenSSL and CA certificates. They need outbound HTTPS to the panel. The panel server can also be a forwarding server.
- **A build machine:** Linux with at least 4 GB of memory and the same CPU type as your servers, running the same Linux release as your servers or an older one.

The project publishes source code and version tags, not ready-made binaries, so you build and sign your own package.

All commands below run as `root` in Bash on Debian or Ubuntu. Replace `panel.example.com`, the version and the IDs with your own values.

### 1. Build and sign a package

On the build machine, install the build tools:

```sh
apt-get update
apt-get install --yes git curl ca-certificates build-essential pkg-config clang libclang-dev openssl python3
```

Set `V` to the release you are installing (for example `V=0.141.9`). Check out the `v$V` tag of the Relay source into `/root/relay-build-$V` and change into that directory; [step 2 of the Deployment guide](DEPLOYMENT_GUIDE_EN.md#2-build-and-sign-a-release-package) shows the exact `git clone` command. Install Rust if it is missing, then build with the Rust version the project's CI uses:

```sh
. "$HOME/.cargo/env"
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 build --locked --release --bin relay --jobs 2
./target/release/relay build-info
```

The first time only, create your signing key pair:

```sh
python3 scripts/relay_deploy.py keygen --directory /root/relay-signing
```

`signing-private.pem` stays on the build machine; back it up offline. `signing-public.pem` goes to every server. Sign every later version with the same key. Then pack the build:

```sh
python3 scripts/relay_deploy.py pack \
  --binary target/release/relay \
  --signing-key /root/relay-signing/signing-private.pem \
  --source-revision "$(git rev-parse HEAD)" \
  --output /root/relay-linux-$V.tar.gz
```

Copy the package, the public key and the `scripts` folder (the installer and its `scripts/deployment/` folder) to each server:

```sh
SERVER=203.0.113.10   # the panel server's IP
ssh root@$SERVER 'install -d -m 700 /root/relay-install'
scp /root/relay-linux-$V.tar.gz /root/relay-signing/signing-public.pem root@$SERVER:/root/relay-install/
scp -r /root/relay-build-$V/scripts root@$SERVER:/root/relay-install/
```

### 2. Install the panel

On the panel server, make sure the runtime tools are present:

```sh
apt-get update && apt-get install --yes python3 openssl ca-certificates curl
```

Then, with `V` set to the same version as before, create the panel's settings so that it listens only inside the server:

```sh
cd /root/relay-install
echo '{"listen":"127.0.0.1:18090","behind_tls_proxy":false}' > controller.json
```

Check first; these two commands change nothing:

```sh
python3 scripts/relay_deploy.py verify --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py preflight --role controller --config controller.json \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
```

Continue only when preflight shows `"ready": true`; otherwise fix the listed `errors`. Then install, start and enable the panel:

```sh
python3 scripts/relay_deploy.py install --role controller --config controller.json \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py start --role controller
python3 scripts/relay_deploy.py enable --role controller

curl -s http://127.0.0.1:18090/ | head -c 200   # should print the start of the panel's HTML page
```

The panel now runs as the service `relay-platform-controller.service` under its own user. Its data lives in `/var/lib/relay-platform/controller/`.

### 3. Add HTTPS

Put a web server in front of the panel to hold the certificate. With Caddy, which gets and renews certificates by itself:

```sh
apt-get install --yes caddy
cat > /etc/caddy/Caddyfile <<'EOF'
panel.example.com {
    reverse_proxy 127.0.0.1:18090
}
EOF
systemctl reload caddy
```

If the server uses a firewall, keep SSH open and allow web traffic. With `ufw`:

```sh
ufw allow OpenSSH
ufw allow 80,443/tcp
ufw enable
```

Port 18090 must stay closed to the internet. For nginx with certbot, see [option B in the Deployment guide](DEPLOYMENT_GUIDE_EN.md#option-b--nginx-and-certbot).

### 4. Sign in

The username is `admin`. The first password is in a private file on the panel server:

```sh
cat /var/lib/relay-platform/controller/admin-password.secret
```

Open `https://panel.example.com` and sign in. Then go to **Account security**, use **Change password** to choose your own password, and turn on **Enable two-step verification**.

If you lose the admin password later, see "I lost the admin password" in the [FAQ](#faq).

### 5. Add your first server

**In the panel:**

1. Open **Nodes** and click **＋ Enroll node**.
2. Enter a name. Under **Connection defaults for new rules**, enter the server's public IP or host name without a port. New forwardings take their ports from 20000–29999 unless you change the range under **Port range / NAT / listen IP**.
3. Keep **Availability first (recommended)** unless you need strict leases (see [Run policy](#run-policy-availability-first-or-strict-lease)). This choice cannot be changed later.
4. Click **Create node**. Copy the node ID from the **Node startup command** and the one-time enrollment token, then click **I saved the token**. The token is shown only once.

**On the forwarding server,** copy the same files to `/root/relay-install`, set `V` to your version, then:

```sh
cd /root/relay-install
umask 077
read -r -s -p 'Paste the one-time enrollment token: ' token; printf '\n'
printf '%s\n' "$token" > enrollment.secret; unset token
cat > agent.json <<'EOF'
{"controller": "https://panel.example.com", "node_id": "PASTE_THE_NODE_ID", "poll_seconds": 5}
EOF
```

If the agent runs on the panel server itself, use `"controller": "http://127.0.0.1:18090"`; plain HTTP is accepted only for a local panel. Then check, install and start:

```sh
python3 scripts/relay_deploy.py verify --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py preflight --role agent --config agent.json \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py install --role agent --config agent.json \
  --enrollment-token-file enrollment.secret \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py start --role agent
python3 scripts/relay_deploy.py enable --role agent

journalctl -u relay-platform-agent -n 20 --no-pager
```

Within a few seconds the server shows as online in **Nodes**. Wait until its applied revision matches the desired one. After enrollment the agent keeps its identity in `/var/lib/relay-platform/agent/`, so restarts and upgrades need no new token.

### 6. Create your first forwarding

This test forwards a public port on the new server to a small web page on the same server. On the forwarding server, start a temporary test site and leave the terminal open:

```sh
relay_demo_dir=$(mktemp -d /tmp/relay-demo.XXXXXX)
printf 'relay-forwarding-ok\n' > "$relay_demo_dir/index.html"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$relay_demo_dir"
```

In the panel:

1. Open **Forwarding rules** and click **＋ New forwarding**.
2. Under **One server only**, choose **Single-VPS port forwarding**.
3. Select the server you enrolled, set the exit service to **Forward to fixed targets**, and enter `127.0.0.1:18080` as the destination. Choose TCP for this HTTP test.
4. The address and port fill in automatically. To pick the port yourself, open **Advanced: ports, source limits and VPS address** on the server's card and tick **Set addresses and ports manually for this path**.
5. Click **Preview changes**, check the diagram, then click **Publish these changes**.

Relay does not open firewall ports. Allow the forwarding's TCP port in the server's firewall and in your hosting provider's security group.

### 7. Check that it works

From your own computer, replacing the address and port with the ones the panel shows:

```sh
curl --fail --max-time 10 http://ENTRY_VPS_IP:PORT/
```

You should see `relay-forwarding-ok`. On **Forwarding rules → All forwarding**, the arrow from the client now shows the entry's inbound connections (for example "Inbound 100%"), and the arrow after the server shows how many of its connections to the target succeeded in the last hour. **Traffic ledger** shows the bytes the rule carried. When you are done, disable or delete the forwarding and stop the test site with Ctrl+C.

The [panel tutorial](PANEL_TUTORIAL_EN.md) continues with forwarding to another server, UDP, and two-hop paths.

---

## Core features

### Servers and their settings

The **Nodes** page lists every server with tabs **All**, **Online**, **Needs attention** and **Awaiting enrollment**. Click a server to open its status, profile and every task for it.

#### Run policy: availability first or strict lease

You choose the policy when you create a server, and it cannot change afterwards.

| Policy | Behaviour |
| --- | --- |
| **Availability first** (default) | Keeps forwarding with its last configuration while the panel is unreachable, and starts forwarding at once after a crash. It cannot enforce shared budgets strictly while disconnected, and it does not support pausing or an expiry date. |
| **Strict lease** | Forwards only while it holds a lease from the panel. If the panel is unreachable for about 25 seconds, the server stops forwarding, and after the panel returns it waits one lease period (30 seconds). Needed for pause, expiry and stricter quota enforcement. |

#### Connection defaults, profile and location

- **Connection defaults for new rules:** the address clients or the previous hop use to reach this server, the automatic port range, an optional NAT mapping and a listen IP. They are stored once and reused by every new forwarding. Changing them affects new forwardings, not existing ones.
- **Profile:** a name, types (such as entry, relay, exit, IX or NAT), a group, tags, notes and a cost record. These are labels for your inventory; they do not change routing. You can filter by them and edit many servers at once.
- **City:** shown on the Overview globe. **Set locations** on the Overview sets every server's city in one dialog.
- **Pause execution** and **Expiry** (strict lease only): a paused or expired server stops forwarding within its current lease window. Usage is not reset. After you allow it to run again, an agent that has already exited needs to be restarted.

#### Speed limit and maintenance

- **Node rate limit** (on **Forwarding rules → By server**) caps all of the server's rules together, upload and download combined, in Mbit/s. It can also limit upload and download separately and allow a burst; see [Separate upload and download limits and burst](#separate-upload-and-download-limits-and-burst). It applies to the next read or write without dropping connections, and never slows the agent's own connection to the panel.
- **Maintenance drain** (in the server's details) tells every upstream server that forwards to this one to send new connections to its other targets, while existing connections run to completion. When active sessions reach zero you can restart or upgrade the server, then click **End maintenance**. Clients that connect to this server directly are not moved; switch them another way, for example with DNS.

#### Identity, replacement and deletion

**Node identity** in the server's details shows its enrollment state. You can rotate its credential, revoke it in an emergency, or replace a lost server: revoke the old identity, issue a time-limited token, and start a new agent with the same node ID in a fresh, empty state directory. The node keeps its rules and confirmed usage. See [Node identity](NODE_IDENTITY.md).

A server's details end with a red **Delete node** section. A server still bound to an agent offers **Revoke identity and delete…**, which revokes it first. Other servers offer **Delete node…**. A server that other forwardings, DNS records, subscriptions, templates or budgets still refer to cannot be deleted until those references are removed.

#### How the agent reaches the panel

By default the agent connects straight to the panel's HTTPS address. If a server cannot reach the panel directly, for example a server in mainland China or on an IX line, the agent can reach it through other addresses, such as a TCP forward on one of your relay servers, tried in order (up to 8), or through an HTTP proxy that supports CONNECT. SOCKS proxies are not supported yet. In every case the agent still verifies the panel's HTTPS certificate end to end, so the relay or proxy in between only passes encrypted traffic along. See [the scenario below](#servers-that-cannot-reach-the-panel-mainland-china-ix-lines).

### Forwarding

**Forwarding rules** has two tabs that show the same configuration. **All forwarding** draws each forwarding from the client through every server to its destination. **By server** lists the listeners and services running on one server, its **Version history** and its **Node rate limit**.

#### Creating a forwarding

Click **＋ New forwarding** and choose:

| Choice | What it creates |
| --- | --- |
| **One server only → Single-VPS port forwarding** | Client → server → fixed destination. |
| **One server only → Single-VPS Shadowsocks** | A Shadowsocks service on one server; the client chooses the destination. |
| **Across several servers (multi-hop) → Multi-hop port forwarding** | Client → entry → relays → exit → fixed destination. |
| **Across several servers (multi-hop) → Multi-hop Shadowsocks** | The entry and relays forward encrypted traffic; only the exit runs Shadowsocks. |
| **Other protocols / advanced rule** | The full rule editor: SOCKS5, HTTP CONNECT, VLESS/Reality, Hysteria2 and every other option. |
| **Create from a saved template** | A rule from **Rule templates**. |

In the multi-hop wizard you pick the entry and the exit, and **+ Add relay VPS (optional)** inserts servers between them. Addresses and ports fill in from each server's connection defaults. Click **Preview changes** to see the diagram and every server's changes, then **Publish these changes**. Nothing is published before that, and previewing does not reserve ports. A multi-hop forwarding creates one rule on each server. For Shadowsocks, **Entry client link** on the published forwarding gives clients a link with the entry's address and the exit's key.

#### Several targets and backup lines

A rule can have several targets. They are alternatives, not a sequence of hops.

- **Priority:** lower numbers are tried first. Targets with a higher number are backups, used only when every target with a lower number is unavailable.
- **Weight:** shares traffic between targets of the same priority.
- **Capacity:** an optional maximum number of sessions per target on this server.
- **Existing next-hop rule (optional):** points a target at a rule on another server, which turns the target into the next hop of a multi-hop path.

#### Balancing modes

Priorities are applied first; the balancing mode then chooses among the available targets with the best priority.

| Mode | How it chooses |
| --- | --- |
| **Weighted round robin** | Takes turns between targets in proportion to their weights. |
| **Source IP hash** | Keeps each client address on the same target. |
| **Least connections** | Picks the target with the fewest active connections, adjusted by weight. |
| **Lowest latency (requires health probes)** | Picks the target with the fastest recent health probes, counting probe losses as extra delay. It switches only when another target is more than 10% faster, so new connections don't flap between similar targets. |
| **Random** | Picks one of the available targets with the best priority at random for each new connection, ignoring weights. |

Even without health checks, a target that just failed a real connection moves behind the others for 10 seconds. A target that is slow to connect does not hold up a new connection: after a short delay Relay also tries the next target, and the first to connect is used.

#### Health checks

Turn on a health check in a rule to probe each target on its real path, including TLS, WebSocket and PROXY settings. A TCP check either just connects or sends a request and compares the start of the reply. A UDP check sends a request and expects an exact reply. By default each target is probed once a second, removed after two failures in a row, and readmitted after two successes plus a five-second observation period. New connections and new UDP sessions only go to healthy targets; existing TCP connections are not moved. A target that keeps losing probes without failing outright is marked **Degraded by loss** and used only after cleaner targets of the same priority.

**Target health** shows each target's state, probe round trip, loss and failure reason. Probe traffic is counted separately from customer traffic. See [Target health](HEALTH.md).

#### Pausing, draining and disabling

- **Pause** a target: it takes no new connections at all, not even when every other target is down; its existing connections continue. Choose **Pause until resumed** or **Pause until a set time**; a timed pause ends on the server's own clock without publishing again. A paused target is still probed, so you can see whether it is ready. If every target of a rule is paused, the rule refuses new connections and the panel warns you.
- **Maintenance drain** on a target: new connections prefer the rule's other targets, while existing connections continue. If every target is draining, traffic is still served.
- **Disable** a forwarding to stop it while keeping its settings.
- **Delete** a forwarding from **All forwarding**. A forwarding that crosses servers is deleted in two steps: the first **Delete** stops the whole route, and pressing **Delete** again after the servers confirm removes its rules. Hops that another forwarding also uses are kept.

#### Changing a published route

You cannot change the listener, reachable address, next hop or transport of a published multi-hop rule while it is running. Disable the forwarding, wait until its servers confirm the change and report no active sessions, then edit, preview, publish and enable it again. The session check currently covers every session on those servers, not only this forwarding's. Changes to targets, weights and balancing of an ordinary rule apply to new connections without this step.

#### Ports, transports and bandwidth aggregation

- **Port ranges:** one rule can listen on up to 256 consecutive ports, sharing one quota and speed limit. Targets use the same port, or the same offset from the first port.
- **Outbound address:** a rule can send its traffic from a specific source IP or network interface of the server.
- **TLS and WebSocket:** an entry or a target can use TLS (with your own CA and optional client certificates), WebSocket or WSS. Certificates and private keys stay in the agent's `tls` directory; see [WebSocket](WEBSOCKET.md).
- **PROXY protocol:** pass the client's original address to the next hop or the destination with PROXY v1/v2; see [PROXY protocol](PROXY.md).
- **Multipath aggregation:** Relay's own multipath protocol carries one connection over up to eight mutually authenticated TCP subflows between two servers, either splitting data across them or copying it to each, with separate upload and download weights per path. Each path can leave through its own source address or interface. Different ports do not guarantee independent links; your servers' routing has to provide separate paths. See [Multipath](MULTIPATH.md).
- **Linux MPTCP** (optional feature): each rule can set inbound and outbound MPTCP to off, prefer or require. **MPTCP extra paths** lets a server use additional local addresses for MPTCP, once its permission file is installed. See [MPTCP](MPTCP.md).

#### One rule on several entry servers

When the same service should be reachable through several entry servers, make it a **shared rule**. Each entry server is a *line*. Every line runs the same rule on the same port, and you create, edit, pause and delete it once. The **Shared rules** section sits below the list on both **All forwarding** and **By server**.

1. Click **＋ New shared rule**. The usual rule editor opens with **1. Name, lines and port** at the top.
2. Enter a name and tick the servers under **Lines (entry servers)**.
3. Click **Auto pick** to get the lowest port that is free on every selected server inside their port ranges, or type a port and click **Check**. The table shows for each line whether the server is online, its port range, whether the port is free, and whether the rule passes validation. A port outside a server's range is only a warning, so a shared port such as 443 is fine. Checking does not reserve the port; saving checks again.
4. Fill in the targets, protocol and limits as for any rule, then click **Create and publish to every line**. All servers change together: if the port is taken on one line, nothing is published and the table names that line.

To turn an existing rule into a shared rule, open **By server** and click **Extend to several lines…** on the rule. It becomes the first line and keeps its ID, port and traffic counters; the servers you tick get a copy on the same port.

Each shared rule shows **Shared rule · N lines**, the state of every line, its entry addresses with **Copy all**, and **Edit**, **Pause** / **Resume** and **Delete**:

- **Edit** changes every line at once and can add or remove lines. Changing the port moves every line to the new port and restarts each line's traffic counters, so move your clients first.
- Each server still holds an ordinary rule, and you can edit or delete it on its own. The shared rule then shows **Lines differ** with the fields that differ, or marks the line as gone; the next **Save to every line** makes them the same again.
- **Delete** lists the lines and ports it removes. Tick **Delete only the shared rule and keep the rule on each line as an ordinary rule** to keep the rules.

Each line listens on the listen IP from its server's connection defaults, or on every address. Speed limits and quotas apply to each line separately. A shared rule does not choose an entry for your clients and does not fail over between entries; use DNS or subscriptions for that. Shared rules use one port, not port ranges, and do not cover managed protocol services. See [Shared rules](SHARED_RULES.md).

#### Server groups and saved chains

An **endpoint group** is one layer of candidate servers, for example your relay servers in Hong Kong or your exit servers in Japan. The servers of a group are alternatives: the previous hop picks one of them, and traffic does not pass through them one after another. A **chain** puts groups in order as layers, so one forwarding runs client → entry server → a layer 1 server → a layer 2 server → … → destination. Save the layout once and reuse it for every new forwarding. The **Endpoint groups & chains** section sits below **Shared rules** on **All forwarding**.

1. Click **＋ New endpoint group**, enter a name and add the servers under **Member servers (in order)** with **Add server**. **Move up**, **Move down** and **Remove** change the list. Make one group per layer.
2. Click **＋ New chain**. For each layer choose **Layer N · endpoint group** and **How the previous hop chooses in this layer**, which is one of the balancing modes above; **＋ Add layer** adds the next layer. Leave **Enabled: new forwardings can be built from this chain** ticked.
3. Click **New forwarding from this chain** on the chain, or **＋ New forwarding** → **From a saved chain** → **Use a saved chain**. Choose the chain, the entry server, a name, the protocol, the destination and, if you like, the entry port; the panel picks the remaining ports and addresses from each server's connection defaults.
4. Click **Preview changes** to see the whole path diagram and the change on every server, then **Publish these changes**. The entry and every server of every layer get one new ordinary rule that targets all servers of the next layer; the last layer targets the destination. All servers change together: if a port is taken or a server's configuration changed since the preview, nothing is published.

A forwarding built from a chain shows **Chain · name** on **All forwarding**, and the chain lists it under **Forwardings built from this chain**. You can edit, disable or delete its rules like any other multi-hop forwarding.

Limits: a group has 1–32 servers of one tenant; a chain has 1–6 layers; a group can be only one layer of a chain and a server can be in only one layer; the entry server cannot be in the chain; one forwarding can touch at most 64 servers. Chains build plain TCP/UDP forwarding only, without WS/WSS tunnels, multipath or managed protocol services between servers. A layer that chooses by **Lowest latency** gets a connect probe automatically and needs TCP. Disabled chains cannot build new forwardings.

Changing a group or a chain does **not** change forwardings already built from it. When a layer's group has gained or lost servers since a forwarding was built, the chain's list marks the forwarding **Group members changed** and names the servers added and removed, and its card on **All forwarding** shows the same mark. To use the new members, build the forwarding again from the chain and then delete the old one. A group that a chain uses cannot be deleted; deleting a chain keeps every rule built from it. See [Endpoint groups and chains](CHAINS.md) (Chinese).

### Proxy services and protocols

Proxy services let the client choose the destination. They have no fixed targets, and by default they refuse to connect to loopback, private and link-local addresses. All of them use the same quotas, speed limits, source and destination rules and metering as ordinary forwarding.

| Service | Built in? | Notes |
| --- | --- | --- |
| **Shadowsocks** | Yes | 2022 methods (`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`) and legacy AEAD methods; TCP and UDP; replay protection. **Share link** gives an `ss://` link. An optional UDP-over-TCP mode helps on networks that break UDP fragments. One key per port; multiple users per port and plugins are not supported. See [Shadowsocks](SHADOWSOCKS.md). |
| **SOCKS5** | Yes | CONNECT, BIND and UDP ASSOCIATE, optional username and password. The first UDP datagram claims an association and must come from an address the rule accepts (its source lists and any firewall sets), so a client whose UDP leaves from a different address than its TCP connection is refused. See [SOCKS5](SOCKS5.md). |
| **HTTP CONNECT** | Yes | HTTP/1.x proxy with optional Basic authentication. See [HTTP CONNECT](HTTP_CONNECT.md). |
| **HTTP/2 CONNECT** | Yes | Basic credentials and/or Bearer tokens (only the tokens' hashes are stored), optional mutual TLS, a stream limit per rule. See [HTTP/2](HTTP2.md). |
| **VLESS** (TLS or Reality, optional Vision), **Hysteria2**, **TUIC v5**, **AnyTLS**, **Trojan**, **VMess** | Needs the optional engine | Runs through sing-box 1.14.4 installed on the server. See below. |

**Managed protocols** need the sing-box engine on the server that provides the service. Stage it with `python3 scripts/stage_protocol_engine.py --directory ./engine-package --target linux-amd64`, install the binary at an absolute path owned by the operator, and point the agent at it (the agent setting `protocol_engine` or the `RELAY_PROTOCOL_ENGINE` variable). One engine process serves up to 64 such rules on a server. Applying a change restarts the engine briefly, which interrupts its open connections. With Reality, the camouflage site's traffic also passes through Relay and counts against the same quota, so allow its address if you use a destination allow list. Firewall rule sets refuse clients before the engine. See [Protocol gateways](PROTOCOL_GATEWAYS.md).

Protocol options in this release:

- Hysteria2 rules support Salamander obfuscation, and a masquerade that answers ordinary web visitors with a fixed page you write. Masquerading as another website is deliberately not offered, because the engine would reach that site outside Relay's accounting and access rules.
- TUIC rules let you choose the congestion control and turn on 0-RTT.
- Reality rules accept several short IDs and a limit on how far a client's clock may drift.
- VLESS (including Reality), VMess, Trojan, Hysteria2 and TUIC rules have a **Share link** with a QR code for importing into client apps. AnyTLS has no widely used link format, so use a subscription for it. Server-side secrets such as the Reality private key never appear in a link.
- The sing-box and Clash/mihomo subscriptions carry the matching client settings (obfuscation, congestion control, short ID).
- Surge subscriptions carry VMess, Trojan, TUIC, Hysteria2 and AnyTLS rules (Surge has no VLESS), and V2Ray and Shadowrocket subscriptions carry each rule's share link (not AnyTLS). Other combinations are listed as skipped with the reason.

Client exports never contain Reality private keys, local TLS keys or the agent's internal bridge credentials.

#### Egress proxy

Normally the server that runs a proxy service connects to each destination itself. With an **egress proxy**, it reaches destinations through another SOCKS5 proxy instead: client → your proxy service → upstream SOCKS5 proxy → destination. The client still chooses the destination; the upstream only makes the connection for it. Use it when the destination should see the upstream's address rather than your server's.

- **Where:** in the rule editor of a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks service, open **Egress proxy (reach destinations through an upstream proxy)** and choose **SOCKS5**. Other rules do not have this section.
- **Upstream proxy addresses:** one `host:port` per line, up to 8. IPv6 addresses go in brackets, such as `[2001:db8::1]:1080`. They are tried in order: when one cannot be reached, the next is used, and one that just failed is tried last for 10 seconds.
- **Upstream username and password:** leave both empty if the upstream needs no login. All addresses share them. They are not the login your own users type for your proxy service.
- **Import link:** paste a link such as `socks5://user:pass@proxy.example.com:1080` and choose **Import link**. The address is added to the list, and the username and password are filled in.
- **Rules still apply first:** your destination allow and deny lists, and the setting that refuses private addresses, check the real destination before anything goes to the upstream.
- **Domain names:** while the service refuses private destinations (the default), your server looks the name up itself, checks the addresses and sends only those to the upstream, so your server's DNS sees the names. If the service allows private destinations and your destination lists have no IP entries, names go to the upstream unresolved.
- **TCP only:** UDP is never sent around the upstream. Turning on the egress proxy switches the rule to TCP and turns off Shadowsocks UDP over TCP; SOCKS5 UDP and BIND requests are refused.
- **What stays the same:** traffic counting, quotas, budgets and speed limits work exactly as without an egress proxy. A failed upstream connection, a wrong password or an error reply counts as a failed connection, and the reason names the upstream but never the password.
- **Seeing it:** the rules table shows an **Egress proxy · address** badge, and **Connections…** lists the upstream as each session's next hop.
- **Older agents:** the server running the service needs the agent of this release. Until it has reported in, the panel refuses to publish and says why, for example “The agent on server Tokyo is too old for egress proxies; upgrade it first”, and the editor warns about it. Rules without an egress proxy keep working with every agent.
- **Not yet supported:** Hysteria2, TUIC and Juicity upstreams, and choosing another rule as the upstream. Rules in a cross-panel share cannot have an egress proxy.

See [Egress proxy](EGRESS_PROXY.md) (Chinese) for the details.

### Client subscriptions

**Client subscriptions** turns a user's Shadowsocks and managed-protocol rules into one link that a client app imports and refreshes. The link contains server addresses, ports and keys, never panel or node credentials. Other rules, such as plain port forwarding, are listed as skipped with a reason.

1. Click **Create subscription**, choose the owner and a format, and optionally a name prefix, node tags to include, a host name that replaces every server address (useful behind NAT or with one domain), UDP, and an expiry of 1 to 3650 days.
2. Use **Preview** to see the generated content and the rules that were skipped, each with a reason.
3. Give the link to the user. Treat it like a password.

| Format | Contents |
| --- | --- |
| V2Ray (Base64) and Shadowrocket | `ss://` links for Shadowsocks rules |
| Clash / mihomo (Clash Meta) | YAML with proxies, a `Relay` group and rules; also managed protocols |
| sing-box | JSON outbounds; also managed protocols |
| Surge | A complete managed profile that Surge refreshes daily, with Auto and Fallback groups and rule-based routing (Apple services and the local network go direct; mainland China has its own group, direct by default) |

A subscription can also **chain your own proxies**: add up to 8 SOCKS5 or Shadowsocks proxies, and the sing-box, Clash/mihomo and Surge formats export each as an entry the app reaches through a Relay server (app → Relay server → your proxy → website). V2Ray and Shadowrocket cannot express a chain and list these proxies as skipped.

Managing links:

- **Edit** changes a subscription's name, format, template, source allowlist and expiry; the link itself stays the same.
- When the subscription's owner has a plan or a user traffic budget, the link also sends the usage header that many proxy apps read, so the app shows traffic used, the total allowance and the plan's end date. Relay counts upload and download together, so the app shows the whole amount as download.
- You can restrict which source addresses (IP ranges) may fetch a link. A fetch from anywhere else gets the same answer as a link that does not exist.
- **Rotate link** issues a new link. You can let the old link keep working for up to 24 hours so clients have time to switch.
- Each user can have up to 20 subscriptions. Each link may be fetched 60 times a minute. Expired or deleted links, and links of disabled users, stop working.

Your reverse proxy's access log may record the link's token, which is part of the URL path, so turn off or mask access logging for subscription links. See [Client subscriptions](SUBSCRIPTIONS.md).

### Traffic quotas, budgets and speed limits

Relay counts the application data it accepts, upload and download together. Protocol overhead (TLS, Shadowsocks framing and so on) is not counted.

| Limit | Where | Applies to |
| --- | --- | --- |
| Rule quota and expiry | Rule editor | One rule. Blank quota is unlimited; `0` blocks traffic. |
| Rule rate | Rule editor | All connections of one rule, in bytes per second (12500000 bytes/s is 100 Mbit/s). Combined, upload, download, and an optional burst. |
| Connection and session limits | Rule editor | Concurrent TCP connections and UDP sessions of one rule. |
| **Node rate limit** | **Forwarding rules → By server** | All rules on one server, in Mbit/s. Combined, upload, download, and an optional burst. |
| **Total rate limit** | **Users & permissions** | One user across every server, in Mbit/s. Combined, upload or download; no burst. Every hop of a multi-hop path applies it, so a path can run slower than the limit. |
| Shared budget | **Shared budgets** | Total bytes for a user, a tenant or a server, across every server. |

When several limits apply, the strictest wins. Under a busy speed limit, bandwidth is shared evenly by bytes sent, first between users and then between each user's connections, so one user opening many connections does not crowd out others, and a connection that happens to read less data at a time still gets the same share. New connections wait behind those already waiting, so opening connection after connection does not hold up a long transfer. Small reads such as interactive traffic are not queued behind large transfers, but they count toward the share, so a flood of small packets cannot crowd out other connections either.

**Shared budgets** spread one byte total across several servers. The panel hands each server reservations, and each server deducts traffic locally before forwarding it, so the total holds even under load. To add a budget, first disable the affected rules and wait for the servers to confirm, then create the budget and enable the rules again; the panel attaches the budget automatically. On a multi-hop path every hop counts against a budget that covers it, so a byte crossing three servers of the same user counts three times. See [Shared budgets](BUDGETS.md).

With the optional **Plan entitlements** feature, a paid plan order becomes the buyer's traffic budget: renewals add traffic and extend the expiry, and refunds remove that order's traffic and days. See [Wallet, plans, orders](#wallet-plans-orders-discount-codes-and-gift-codes).

#### Separate upload and download limits and burst

Each speed limit (a rule's **Combined rate**, a server's **Node rate limit** and a user's **Total rate limit**) has a **Limit mode**: **Combined upload and download** (as before), **Separate upload and download**, or **Combined and separate** (a combined limit plus upload and download limits). Fill in only the limits you want; a blank one is unlimited, and every limit you set applies at once.

- **Upload** is what this hop's client sends toward the target; **download** is what comes back from the target. UDP works the same way. On a multi-hop path each server counts relative to its own client, so your users' outgoing traffic is upload on every hop. For a proxy service (Shadowsocks, SOCKS5 and the others), what the client sends to its destination is upload.
- **Where:** the rule editor (bytes/s), **Node rate limit** on **Forwarding rules → By server** (Mbit/s), **Total rate limit** on **Users & permissions** (Mbit/s), **Access & limits** of a reverse tunnel (bytes/s), and **Total bandwidth** of a cross-panel share (Mbit/s, upload and download without burst). Shared rules and rule templates keep the limits of the rule they copy.
- **Burst (optional)** is available for rules and servers. Open it under the limits and enter a **burst rate** and a **burst time / seconds** for the combined, upload or download limit; the burst rate must be above that limit, and the burst time is 1 to 86400 seconds. The burst credit is (burst rate − limit) × burst time and starts full. While credit is left, traffic can run up to the burst rate; sending above the limit spends credit, sending below the limit earns the difference back, and with no credit left the limit applies. For example, with a burst of 100 Mbit/s, a limit of 30 Mbit/s and a burst time of 5 minutes, a full burst runs at 100 Mbit/s for 5 minutes and then at 30 Mbit/s. The burst comes back while the link runs below 30 Mbit/s; from idle, a full burst is back after about 11.7 minutes.
- **Total rate limit** has no burst. Its upload and download totals are each split between the servers that carry the user's rules, like the combined total, and the dialog lists **Upload shares** and **Download shares** per server. The servers' shares never add up to more than the total.
- **Seeing them:** the rules table's **Quota / rate limit** column and the server's **Node rate limit** badge list every limit, for example `Upload 10 Mbit/s · Download 50 Mbit/s (burst 80 Mbit/s · 300 s)`. When an agent reports it, **Download burst credit 50%** (or **Combined** or **Upload**) shows how much burst is left; below 100% the burst is in use or still coming back.
- **Older agents:** separate and burst limits need the agent of this release on every server involved. Until a server's agent has reported in, the panel refuses to publish them there and says why, for example “The agent on server Tokyo is too old for separate upload/download or burst speed limits; upgrade it first”, and the **Node rate limit** dialog warns about it. A combined limit still works with every agent. While a user has an upload or download total, their enabled rules can only be published on servers with the new agent.
- Metering, quotas and shared budgets do not change: traffic is still counted in both directions and against the same quotas.

See [Speed limits](RATE_LIMITS.md) (Chinese) for the details.

#### Plan traffic cycles and automatic top-up

With **Plan entitlements** on, a plan can give its traffic per cycle instead of once, and can sell extra traffic from the wallet when a cycle runs out.

- **Plan editor** (**Wallet & orders → ＋ New plan** or **Edit**): **Traffic reset** is **No reset (traffic lasts until expiry)**, the default and the behaviour of every existing plan; **Follows the billing period**, which resets at the end of every paid period; or **Every N days** with **Reset interval / days (1..366)**. For automatic top-up fill in **Automatic top-up: bytes per top-up (blank for none)**, **Price per top-up (CNY)** and **Top-ups per cycle at most (1..1000)**. A top-up needs the plan's traffic and a reset policy. The **Plans** list shows both in its **Traffic reset** column.
- **Each cycle** starts again with the plan's traffic. Unused traffic does not carry over, and a renewal extends the expiry without adding traffic. The panel checks for due resets every minute. If it was down across several resets, it resets once into the current cycle.
- **My plan** shows **Used this cycle**, **This cycle's traffic** (including top-ups), **Remaining**, **Next reset**, **Top-ups this cycle** against the cap, and the dates of the current cycle. Traffic that servers have reserved but not reported yet also counts against the cycle, including reservations they held when the cycle began. Users switch top-up on with **Turn on “Top up automatically when used up”** and off with **Turn off automatic top-up**.
- **Automatic top-up** runs when a cycle has less than one reservation left and the user has switched it on. The wallet is charged, a **Top-up** order appears under **Orders** (**Type**), and the cycle's traffic rises at once. A top-up never extends the expiry, is cleared at the next reset, and cannot be refunded with **Refund**; adjust the wallet instead. When it cannot run, **My plan** shows why under **Last automatic top-up did not run**: the plan has no automatic top-up, it is switched off, this cycle's limit is reached, or the wallet balance is too low. The shared budget then runs out and raises the **Shared budget exhausted** alert with the same reason; the **Shared budget near its limit** alert also counts from the start of the cycle.
- **Plan entitlements** (system administrators) shows each user's **Current cycle** with the next reset, whether automatic top-up is on, the top-ups used against the cap and the last failure. **Reset traffic now** starts a new cycle from now and clears its top-ups without changing the expiry; **Turn on top-up** and **Turn off top-up** switch automatic top-up for that user.
- A user with an active plan cannot buy a plan that resets differently until the current one ends. Shared budgets keep counting every cycle's bytes; cycle numbers appear on **Wallet & orders** and in client subscription usage. See [Commerce](COMMERCE.md) and [Shared budgets](BUDGETS.md).

### Access control

- **Source addresses:** each rule has allowed and denied source CIDR lists. Denied entries win. A blank allow list admits every source that is not denied. On a relay hop, the source is usually the previous server.
- **Destinations:** each rule can allow or deny destination IPs, CIDR ranges, exact domains and domain suffixes (`*.example.com`), plus destination ports and port ranges. Deny wins, and every address a domain resolves to is checked. This applies to fixed targets and to every proxy service. See [Destination ACL](DESTINATION_ACL.md).
- **Domain suffixes:** `*.example.com` matches subdomains such as `api.example.com` only, not `example.com` itself and not lookalikes such as `badexample.com`. Since this release that holds for deny lists too: a deny entry `*.example.com` no longer blocks `badexample.com`, so add such names on their own if you relied on that.
- **Private destinations:** proxy services refuse loopback, private and link-local destinations (including cloud metadata addresses) unless you allow them per rule.
- **Client certificates:** an entry with TLS can require a certificate from your own CA.
- **PROXY protocol sources:** a rule only accepts PROXY headers from the source ranges you trust.
- **Firewall rule sets:** for lists you use in many places, open **Firewall rule sets** under Forwarding setup. A set has a name, a direction (**Inbound** checks who is connecting, **Outbound** checks where your server connects to), a list of allow or deny rules and a **default action** for anything no rule matches. Rules are checked from the top and the first match decides, so put exceptions above broader rules; the arrows move a rule up or down. A system administrator attaches sets to a server (in the server's settings or with **Bind…**); a tenant administrator attaches their own inbound sets to their own rules in the rule editor. A connection has to pass every set that applies plus the rule's own lists, so a set can only make a rule stricter. When you edit a set, every server that uses it updates by itself; **Server policies** shows **Applied** once the server has confirmed the change, or why not yet (waiting, offline, or the agent is too old and must be upgraded first). The **Rule tester** tells you, for an address you type, which rule of which set decides. Refusals appear in the blocked-connection records as **Refused by a firewall rule set**. If clients come through a load balancer that sends PROXY headers, the server's inbound set checks the load balancer as well as the client, so allow the load balancer's address in it. A reverse tunnel's target is checked against the private server's outbound set: its agent connects only to addresses the set allows, and a refusal appears in the public server's blocked-connection records. Protocol gateways check each client's own address against the server's and the rule's inbound sets before the protocol engine sees any of it, so a refused client gets no TLS or QUIC handshake and no Reality camouflage site. Older agents do not do either: the panel then refuses new bindings, gateways and tunnel changes they would leave unchecked (upgrade the agent first), keeps the ones that already run and lists them under **Server policies** as not covered. Name entries match the name as the client sent it, and a resolver with a search list can turn a short name such as `db` into `db.internal.corp`, so block internal services with address ranges. Don't downgrade the agent on a server that uses rule sets. In tests with the 0.149.0 agent, a server whose rules had rule sets stopped forwarding because the older agent would not start; reinstalling the newer agent on the same server brought it back with its sets. Removing the sets from the server's rules and waiting until the server applied that change let the 0.149.0 agent start, but it ignores server-level sets, so sources they refused are let in. See [Firewall rule sets](FIREWALL.md) (Chinese).

### DNS, DDNS and the authoritative DNS pool

**DNS management** (system administrators) keeps DNS records in step with your servers. Relay supports Cloudflare-compatible provider APIs and DNS webhooks: a receiver you run that checks a signed request and applies whole record sets to your own DNS, for example BIND through RFC 2136.

1. **Add provider** with an API token. The token is never shown again after saving. An optional **Minimum TTL** raises any lower record TTL (Cloudflare's automatic TTL is left alone). **Test** checks the token and lists the zones it can see.
   For a **DNS webhook**, enter the receiver's final URL, a secret of at least 32 bytes, the zones the receiver manages and a request timeout (15 seconds by default). **Test** sends a signed ping only; it does not prove the receiver can write DNS. Records in a webhook zone use full names inside the zone, values with the same name and type are sent together with the lowest of their TTLs, and Cloudflare proxying is not available. Changing the URL sends every record again to the new receiver; the old one keeps what it had. Before downgrading to 0.147.0 or earlier, delete webhook records, zones and providers: older versions cannot read a webhook provider, so their DNS provider list fails and cannot delete it. If you already downgraded, upgrade again, delete them, then downgrade.
2. **Add zone** in one of two modes. **Observe** reads the provider and reports what it would create, update or delete without writing anything. **Apply** creates, updates and deletes the records Relay manages. Relay only touches records it created (marked with a `relay:` comment), never other records with the same name.
3. **Add record:** an A, AAAA or CNAME record with a TTL.
4. Zones are checked automatically every 30 seconds: apply-mode zones write only what changed, and observe-mode zones just record what they would do. **Sync now** runs a check immediately. Each zone shows when it was last checked, and each record shows its state and why (published, waiting for the confirmation window, removed, or held back).

**DNS health gating** (optional feature) ties a record to a server and rule. If the server has not reported for 90 seconds, or the rule has no healthy target, apply mode removes the record and recreates it when the server recovers. With **Minimum records to retain**, a failing record is removed only while at least that many valid records remain; otherwise it is kept. Each zone has a **Confirmation window** (60 seconds for new zones, up to 30 minutes): a health-gated record is removed only after failing for the whole window, and restored only after passing for the whole window. If more than half of the records for one name fail at the same moment, which usually means a monitoring problem rather than real outages, Relay holds all removals for that name and says so.

**DDNS:** external scripts can update an A or AAAA record's address through the API (`POST /api/v1/dns/records/{id}/ddns`), and the zone syncs immediately. DNS routes accept only a signed-in system administrator session, not an API token. Relay does not detect a server's public IP by itself.

**Independent authoritative DNS pool** (optional feature) lets your own servers answer DNS for a zone you delegate to them, without a DNS provider. Records can be A, AAAA, CNAME or TXT, and each value can follow a rule's health. A minimum number of values per record, set on the zone, is never withdrawn. The panel lists each name server's state and the delegation records to add at your registrar. Each agent keeps the last answers, so it keeps answering through a restart while the panel is unreachable. Port 53 needs the `deploy/relay-agent-dns.conf` permission file on the server, and DNSSEC is not supported. See [DNS](DNS.md).

### WireGuard networking and NAT traversal

**WireGuard networking** (optional feature, system administrators) joins servers and user devices into private IPv4 networks.

- **Add node:** a server joins once its agent has reported a WireGuard public key. Give it a public endpoint if it has one; leave it empty when it is behind NAT.
- **Add device:** a phone or laptop connects through one public entry server. The panel creates the key pair and shows the configuration and a QR code once; only the public key is stored. A device can also bring its own public key, and **New key** replaces its key pair.
- A network can list up to 4 DNS servers, written into every device configuration.
- Each device can have its own allowed IP ranges (the addresses it sends into the tunnel) and keepalive interval.
- A device can be switched off and on without deleting it; it keeps its keys.
- A device can get an optional preshared key, added when you create it or with **New key**. Its entry server must run an agent of this version or newer.

Two servers connect directly when at least one is public. Two servers behind NAT go through a relay server. The page shows every member's state and every pair's path, last handshake and traffic.

**NAT traversal** (optional feature) lets two servers that are both behind NAT try to connect directly ("hole punching") instead of through the relay. A trial entry carries no traffic until a handshake proves the path. If the attempt fails, or a direct path goes silent for 75 seconds, the pair returns to the relay with the reason shown and retries later (5 minutes at first, doubling up to an hour). NATs that pick a new port for every destination cannot be punched.

On the server, the agent only acts after you install `wireguard-tools` and the `deploy/relay-agent-wireguard.conf` permission file. It manages only links named `rwg-*` and never adds default routes, firewall rules or system-wide settings. See [WireGuard](WIREGUARD.md).

### Reverse tunnels and router port mapping

**Reverse tunnels** (Forwarding rules → All forwarding → **Reverse tunnels (NAT traversal)**) publish a service on a server that cannot accept inbound connections, such as a server behind a home router or carrier-grade NAT. Both ends are servers in the panel:

- The **public server** accepts users on the **public port**.
- The **private server** connects out to the public server's **tunnel port** and keeps one encrypted tunnel connection to it. It hands each user connection to the **target**, a `host:port` it can reach: `127.0.0.1:8080` is the private server itself, and `192.168.10.20:8080` is another machine on its LAN.

Click **New reverse tunnel**, choose the public and the private server (both in one tenant), and set the public port (**Auto** picks the lowest free port in the public server's forwarding range), the target and the protocol (TCP, UDP or TCP + UDP). **Advanced** holds the tunnel port (29123 by default, shared by every tunnel on one public server) and the listen IP of the public port. Open both ports in the public server's cloud firewall or security group; the tunnel port needs TCP only. The public server needs a forwarding host in its connection defaults, because that is the address the private server dials.

- The tunnel runs on TLS. The public server makes its own key and reports only its fingerprint; the private server pins that fingerprint and then authenticates with a random token per tunnel that the panel sends only to the two servers and never shows.
- The list shows each tunnel's state: **Waiting** with the reason (for example *Agent too old* or *Waiting for the public server's key*), **Connected** with how long, **Error** with the reason, or **Disabled**. It also shows the entry address with **Copy** and the traffic.
- The public end is an ordinary rule on the public server, so traffic goes into the usage ledger and **Access & limits** sets allowed and denied sources, the rate limit and the connection limit. Disabling a tunnel closes the public port; the private server stops connecting out on its next sync and reconnects with backoff whenever the tunnel drops.
- Both servers need agents of this version or newer. See [Reverse tunnels](REVERSE_TUNNELS.md).

**Manual option: the command-line tools.** `relay reverse-mux-server` and `relay reverse-mux-client` run the same tunnel protocol outside the panel, with a shared token file instead of panel-managed keys, and without rule metering or panel-managed limits. On an installed server the program is `/opt/relay-platform/roles/agent/current/relay`. On the public server:

```bash
printf '%s\n' 'long-random-token' > /etc/relay/reverse.token
chmod 600 /etc/relay/reverse.token
relay reverse-mux-server \
  --control-listen 0.0.0.0:19010 \
  --public-listen 0.0.0.0:19011 \
  --token-file /etc/relay/reverse.token
```

On the private server:

```bash
relay reverse-mux-client \
  --server PUBLIC:19010 \
  --target 127.0.0.1:8080 \
  --token-file /etc/relay/reverse.token
```

Clients connect to `PUBLIC:19011`. One control connection carries many client connections. Options add TLS or mutual TLS for the control connection, TLS on the public port, allowed public CIDRs, stream and idle limits and UDP. See [Reverse tunnels (command line)](REVERSE.md).

**Router port mapping:** `relay nat-map` (NAT-PMP), `relay pcp-map` (PCP) and `relay upnp-map` (UPnP IGD) ask a home router to open a port, and `--renew` keeps the mapping alive. They currently request UDP mappings only and support IPv4 only. See [NAT port mapping](NAT.md).

### Cross-panel sharing

**Cross-panel sharing** (optional feature) lets you give another Relay panel a slice of one of your servers, or receive one.

**As the owner,** click **New share** and set the server, a port range (up to 1000 ports), how many rules the receiver may create, the allowed kinds (port forwarding and/or Shadowsocks 2022), optional total bandwidth, total traffic and expiry, and the allowed sources and destinations. Send the receiver the one-time invite code, valid for 24 hours. Your own publishes cannot change or overlap a share. **Pause** disables its rules, and **Revoke** removes them from the server and cuts off the receiver.

**As the receiver,** click **Enter invite code**, then add rules inside the share's limits. The owner checks every request and creates the rule itself, so a receiver cannot widen a share. Shadowsocks rules come back with a key and **Copy link**. Both sides see the traffic statement, and each warns if the owner reports less traffic than before. See [Cross-panel sharing](FEDERATION.md).

### Users, tenants, roles, two-step verification and API tokens

| Role | Can do |
| --- | --- |
| **System administrator** | Everything, across all tenants, including system pages such as DNS, WireGuard, logs and recovery. |
| **Tenant administrator** | Manage the servers, rules, users, templates, announcements and tickets of their own tenant. |
| **Viewer** | Read their tenant's data; no changes. |

The server checks every permission; hiding a page in the sidebar is only a convenience.

- **Users & permissions:** **Add user**, assign a tenant and role, **Reset password**, disable or delete accounts, and set a user's **Total rate limit**. Disabling or resetting signs the user out everywhere and revokes their API tokens. An account that still owns rules or subscriptions cannot be deleted.
- **Account security:** **Change password**, **Enable two-step verification** with an authenticator app (you get 8 single-use recovery codes, shown once), and **Create API token**.
- **API tokens** have scopes (**Read all accessible data**, **Write nodes and configurations**, **Write shared budgets**, **Write users and tenants**) and expire after 1 to 365 days. A token never has more rights than its owner's role. Some areas, such as DNS, commerce, tickets, templates and your own account, accept only a signed-in session. See [API](API.md).
- **Audit log** records who did what and when.
- Sign-in allows 30 attempts per 5 minutes from each visitor. Sessions expire after eight hours.

### Wallet, plans, orders, discount codes and gift codes

**Wallet & orders** is a basic billing layer in one currency (CNY, stored in cents).

- **Plans:** name, description, price, duration and optional traffic. Users buy a plan, which creates an order, and pay with their wallet balance.
- **Wallet:** administrators credit or debit a user's wallet with a reference and description; every change is recorded and a duplicate reference is refused.
- **Refunds:** administrators refund wallet-paid orders back to the wallet.
- **Discount codes:** percentage or fixed discounts with a minimum price, usage limit and validity window.
- **Gift codes:** credit a wallet when redeemed (**Redeem gift code**); each user can redeem a code once.
- **External payments:** a payment gateway can confirm orders through an HMAC-signed callback. Relay does not include adapters for specific payment providers.

Without the **Plan entitlements** feature, paying for a plan only changes the wallet and order. With it on, see [Traffic quotas](#traffic-quotas-budgets-and-speed-limits). Plans do not control device counts or speed. See [Commerce](COMMERCE.md).

### Support tickets and announcements

**Support tickets:** users open a ticket with a subject, message and priority (low, normal or high). Administrators reply publicly or add internal notes that the user never sees, and move tickets between open, pending and closed. Closed tickets accept no new messages until an administrator reopens them. See [Tickets](TICKETS.md).

**Announcements:** **New announcement** posts a message to everyone or to one tenant, with a severity (info, warning or critical) and an optional start and end time. Tenant administrators manage their own tenant's announcements. See [Announcements](ANNOUNCEMENTS.md).

### Templates and batch publishing

**Rule templates** saves a working rule (targets, protocol, TLS, limits and so on) for reuse. Create one with **New template**, or click **Save as template** on a rule. **Use this template** asks for the server, a new name and a listener, shows a preview, and creates a rule with a new identity and a new metering period.

- Templates can contain `{{name}}` variables that you fill in per server.
- Every save creates a version. You can compare two versions (**Diff**) and roll back, which saves the old content as a new version.
- **Bulk apply** publishes a template to up to 100 servers in batches. Options: a first batch by percentage, a check that each server is online and error-free before writing, waiting until each server confirms the new revision, requiring healthy targets after each batch, and automatic removal of the new rules if a batch fails. A failed rollout can be retried without duplicating rules.

These checks confirm configuration and probe results, not real customer traffic. See [Templates](TEMPLATES.md).

### Optional features

Some features start switched off. A system administrator turns them on in **System & help → Optional features**; their settings then appear in the matching forms.

| Feature | What it adds |
| --- | --- |
| **Linux MPTCP** | MPTCP settings in the rule editor |
| **MPTCP extra paths** | Extra local MPTCP addresses in a server's settings |
| **DNS health gating** | Health-gated DNS records |
| **Independent authoritative DNS pool** | Your servers answer DNS themselves |
| **WireGuard networking** | Private networks of servers and devices |
| **NAT traversal** | Direct WireGuard paths between servers behind NAT |
| **Cross-panel sharing** | Sharing server capacity with other panels |
| **Plan entitlements** | Paid plans become traffic budgets |
| **Budget disaster recovery** | Write off reservations of a server run that can no longer report, on **Recovery protection** |

A feature cannot be switched off while a rule or record still uses it. The switches change panel forms and checks only, never server system settings.

---

## Scenarios

### One entry, many exits

Goal: clients connect to one entry address, and the entry spreads them across several exit servers or keeps a backup exit ready.

1. Enroll the entry and every exit server.
2. Create a multi-hop forwarding from the entry to the first exit (**＋ New forwarding → Across several servers (multi-hop)**).
3. On each other exit, create the matching service with **＋ New forwarding → One server only**, which also records the exit's reachable address. If the exits run Shadowsocks, give them all the same method and key, because the client's key has to work on whichever exit it reaches.
4. Disable the forwarding and wait until the entry reports no active sessions. Then edit the entry's rule on **By server**, add a target for each other exit, and choose **Existing next-hop rule (optional)** for each.
5. Give exits the same priority to share traffic, or a higher priority number to keep them as backups. Pick a balancing mode: **Source IP hash** keeps each client on one exit, and **Lowest latency (requires health probes)** follows the fastest exit.
6. Turn on a health check on the entry rule so that a failed exit is skipped. A request-and-reply check travels through the exit to the final service, so it tests the whole remaining path.
7. **Preview changes**, publish, and enable the forwarding again. On **All forwarding**, the entry lists each exit by priority with its current role and success rate.

Every hop meters its own traffic, so a budget covering both the entry and an exit counts each byte twice.

### Servers that cannot reach the panel (mainland China, IX lines)

Some servers cannot open a reliable HTTPS connection to the panel: servers in mainland China, or servers on IX or private lines with no direct route to the internet. The agent can reach the panel another way.

1. Choose a server that the restricted server can reach and that can reach the panel, for example your entry server on the same IX.
2. On that server, create a **Single-VPS port forwarding** whose destination is the panel's HTTPS address (`panel.example.com:443`). Allow only the restricted server's address under **Allowed source CIDRs**.
3. On the restricted server, list that forward's address in the agent's `controller_addresses` setting in `agent.json` (the `--controller-address` option of `relay agent`), in the order to try them. Alternatively set `controller_proxy` to a proxy you already run: an HTTP proxy (`http://host:port`, without a password) or a SOCKS5 proxy (`socks5h://host:port` lets the proxy look up the panel's name, `socks5://host:port` looks it up on the server). A SOCKS5 user name and password go in a separate file named by `controller_proxy_credentials_file`, never in the URL. The panel URL must use a host name, not an IP address, and if it names a port, the forward must listen on that same port. See [Servers that cannot reach the panel directly](DEPLOYMENT_GUIDE_EN.md#servers-that-cannot-reach-the-panel-directly).
4. Keep the forward as plain TCP. The agent still checks the panel's HTTPS certificate end to end, so the relay server only passes encrypted traffic and cannot impersonate the panel.

Choose **Availability first (recommended)** for such servers, so customer traffic keeps flowing if the control path breaks for a while. The data path is unaffected: the restricted server's rules can be any hop of a multi-hop forwarding.

### Private-line mappings: the public port differs from the bound port

Many providers, especially NAT VPS and private-line products, map a public address and port to a different local port on the server. Relay separates the two: the **listener** is what the agent binds, and the **reachable address** is what clients or the previous hop connect to.

- **A whole mapped range:** in **Nodes**, edit the server and open **Port range / NAT / listen IP** under **Connection defaults for new rules**. Set the automatic port range to the local ports and **First public NAT port (blank for same ports)** to the first public port. New forwardings then listen on a local port and advertise the matching public port. This is only correct for one continuous range that the provider already maps one to one.
- **A single mapping:** on the server's card in the wizard, open **Advanced: ports, source limits and VPS address**, tick **Set addresses and ports manually for this path**, and enter the local listener (for example `0.0.0.0:20001`) and the reachable endpoint (for example `PUBLIC_IP:40001`).
- **IX and private lines:** set each hop's reachable address to the address the previous hop actually uses, such as the private-line address, not the public one. Clients only ever use the entry's reachable address.

The panel checks that each upstream target matches the next hop's reachable address, not its listener. It never creates the NAT mapping or opens firewall ports. Subscriptions use the reachable address, or the host name you set on the subscription.

### Servers behind home routers or NAT

The agent only makes outbound HTTPS connections to the panel, so enrollment, configuration and reporting work behind any NAT. What needs planning is how traffic reaches the server's listeners.

- **Reverse tunnel (recommended):** under **All forwarding → Reverse tunnels (NAT traversal)**, create a tunnel with a public server as the entry and the home server as the private server. Users connect to the public server's port; the home server connects out and delivers each connection to a service on itself (`127.0.0.1:…`) or on its LAN. Nothing needs to be opened on the home router. The public end is metered and limited like any rule. See [Reverse tunnels and router port mapping](#reverse-tunnels-and-router-port-mapping).
- **Router port forwarding:** forward the rule's port on the router, then set the server's reachable address to the router's public IP and the mapped port, as in the previous scenario. `relay nat-map`, `relay pcp-map` and `relay upnp-map` can request the mapping from routers that support NAT-PMP, PCP or UPnP, but only for UDP. Map TCP ports on the router by hand.
- **Manual reverse tunnel:** `reverse-mux-client` at home and `reverse-mux-server` on the public server, without the panel. The tunnel itself has no rule metering.
- **WireGuard networking:** add the home server as a member without a public endpoint. It reaches the other members through a public relay server, or directly when **NAT traversal** succeeds. A forwarding rule can then use the home server's WireGuard address as its target. This combination is not part of the automated tests, so check it with a real client.

Carrier-grade NAT usually blocks inbound mappings, and its port behaviour often defeats hole punching, so plan on a relay or a reverse tunnel there.

---

## Help

### Monitoring

- **Overview:** summary cards with sparklines compared with the same hour yesterday; a 24-hour connection dial with successful (teal) and failed (red) connections and the success rate; **Needs attention** with the newest unresolved problem; throughput with a dashed line for yesterday; a globe of located servers; recent events; forwarding paths; trends over 24 hours or 7 days; and the server table.
- **Forwarding rules → All forwarding:** each arrow shows the last hour's success rate of real TCP connections at that hop. Hover for counts and causes. *Refused* means nothing listens at that address, *Timed out* points to firewalls or routing, and *Closed by peer* often means a TLS or WebSocket mismatch. Expand a path for a 24-hour or 7-day strip per hop and **Export CSV**. UDP is not counted here.
- **Target health:** probe state, round trip, loss and jitter for every target.
- **Traffic ledger:** usage per server, rule and metering period, as charts or a table.
- **Prometheus:** an authenticated `GET /api/v1/metrics` exposes server, rule, health, budget and recovery-log metrics.

The panel keeps seven days of five-minute connection history.

### Alerts

**Alerts & notifications** sends notifications when a target becomes unavailable, a server rejects a configuration or a server goes offline. Under **Alert rules** → **Edit rules** you can also turn on alerts for high CPU or memory use, a server about to expire or expired, a shared budget nearly or completely used up, and a DNS record that failed to sync. Each has its own threshold and number of consecutive checks; all are off until you turn them on, and each clears on its own when the condition ends.

1. **Add notification channel:** Webhook (optionally HMAC-signed), Telegram, WeCom, Feishu, DingTalk or email over SMTP with TLS or STARTTLS. A channel can serve all tenants or one tenant.
2. Choose the minimum severity: **Warning and above** or **Critical only**.
3. Click **Test** to confirm delivery.

Problems that appear together are grouped into one message, and the same problem repeating within five minutes counts once. A maintenance window (**Maintenance for 1 hour** or **4 hours**) holds new alerts and sends the unresolved ones afterwards. Failed deliveries retry after 10 seconds, 60 seconds and 5 minutes. Resolved alerts are kept in the panel's memory and start over after a restart. See [Alerts](ALERTS.md).

### Live logs and the diagnostic report

**Live logs** (system administrators) shows the latest log lines of the panel and every server without SSH. Each process keeps its newest 2000 lines in memory, new lines arrive about every 5 seconds, and you can filter by source, level and text and download the result. The system journal on each server keeps the full record.

**Diagnostics** checks everything at once and lists, most severe first: offline servers, rejected configurations, hops below 90% success in the last hour with their main cause, failing probes, CPU or memory shortages, and recent errors. **Download report** saves a JSON file for support or an AI assistant. It never contains passwords, keys or tokens.

On a server, these commands show the agent's state:

```sh
systemctl status relay-platform-agent --no-pager
journalctl -u relay-platform-agent -n 100 --no-pager
ss -lntp
ss -lnup
```

#### Speed tests

Relay can measure how fast a server's line is, and how fast each leg of a forwarding path is, without SSH or extra tools. The test is built into the agent with fixed limits: the panel cannot make an agent run a program or fetch an address of its choosing.

- **Server speed test** (system administrators): **Diagnostics → Speed test**. Choose a **Mode**: **Server ↔ Cloudflare** measures one server against Cloudflare's public speed service (speed.cloudflare.com only); **Server ↔ server** measures the line between a **Testing server (connects)** and a **Peer server (listens temporarily and accepts the connection)**. Then choose the **Direction** (upload, download or both), a duration of 5 to 60 seconds per direction or a data amount of 1 to 1000 MB, and 1 to 8 **Parallel TCP streams**, and click **Start speed test**. Progress shows while it runs; **Cancel speed test** stops both servers at once.
- **Upload** is from the testing server (on a path, towards the last hop, the way your users upload); **download** is towards it. The first 2 seconds of each direction are warm-up and are left out. Each result shows the **average** and the **1-second peak** in bits per second, the bytes and seconds measured, and any streams that failed. **Last 50 speed tests** keeps the history.
- **Path speed test…** is in the actions of a rule under **Forwarding rules → By server** and of a path under **All forwarding**. It measures each segment of the rule's path in turn (entry server → next hop → … → last hop) with the server-to-server test, connecting to the same address the hop's target uses, so the test follows the real route between those servers. It names the **slowest segment** and, when the last hop has a fixed target, shows the TCP connect time from the last hop to that target (no data is sent). System administrators and users who can edit every server of the path may run it; read-only accounts and API tokens without `nodes:write` cannot, and other users run at most one speed test a minute.
- **Not counted, not limited:** test traffic does not pass through any rule. Rule and server speed limits do not apply, and nothing counts towards the traffic ledger, quotas, shared budgets or plans. The path dialog lists the limits configured along the path next to the results so you can compare; a result above a limit is the line's capacity, not what your users get through the rule.
- **Ports and firewalls:** in server-to-server and path tests the receiving server opens a temporary TCP port from its forwarding port range (or a **Test port on the peer** you choose), accepts only connections that carry the test's random token, and closes it when the test ends. Allow that range in its firewall or security group. Both servers need a forwarding host under their forwarding settings; behind NAT, the public port mapping must match the router. Cloudflare tests need outbound HTTPS. Cloudflare limits how much one address can download in a short time, so on a fast server it may stop serving partway through: the result then covers only the part before that and says so, and a test refused from the start asks you to try again in a few minutes.
- **Limits and older agents:** each server takes part in one test at a time. Not available for proxy services, protocol gateways, the public end of a reverse tunnel or rules shared from another panel; the dialog says why. Every server involved needs the agent of this release; otherwise the panel says, for example, “The agent on server Tokyo is too old for speed tests; upgrade it first”. Older agents keep working as before.

See [Speed tests](SPEED_TESTS.md) (Chinese) for the details.

#### Connections and blocked connections

When a user says “it doesn't connect” or a port looks busy, you can see who is connected to a rule right now and what the server refused, without SSH.

- **Connections…** is in the actions of a rule under **Forwarding rules → By server** and of a path under **All forwarding**. The dialog asks the server for the rule's open connections and shows, newest first, each **client** address (the real one when the rule takes PROXY headers), the **protocol**, the **target** and the address actually connected (for SOCKS5, HTTP CONNECT, Shadowsocks and protocol gateways, the **real destination** the client asked for), the **next hop** when the target is another server's rule, when it **started** and for how long, and live **upload** and **download**. Type in the filter box to narrow the list; it refreshes every few seconds while the dialog is open, and **Refresh** asks again. At most 200 connections are listed; above that the dialog says, for example, “200 of 350 shown”.
- Below the list, **Counters (since the agent started)** show the accepted connections and how many completed their inbound setup (PROXY header, TLS or WebSocket handshake), and for each target the attempts, successes, its share of successes (the next-hop distribution), failures by cause and the average setup time, followed by refusals by reason. They start over when the agent restarts; the hourly history is on **All forwarding** as before.
- **Blocked connections** lists what was refused and why: source not in the allow list, source in the deny list (with the matching network), connection or UDP session limit reached, HTTP/2 stream limit reached, quota used up, shared budget refused, rule expired, all targets paused, proxy destination not allowed, and proxy authentication or handshake failed. Each entry shows the last time, the source IP, the reason with a short detail and a count: refusals of the same rule, source and reason within 60 seconds are merged. The dialog shows the rule's entries; **Blocked connections** in the server toolbar of **By server** shows the whole server's, with a rule filter.
- **Who can see it:** everyone who can see the server's rules, including read-only accounts, and API tokens with `read`. Client addresses are personal data: blur them before you share a screenshot.
- **Ending one session:** users who may change the rule (not read-only accounts) see **End** next to each connection. After you confirm, the panel asks the server to end just that session and shows the answer: ended, already gone, the agent restarted (the session ended with it), not answered within 30 seconds (it may still be open; refresh to check), or still open 3 seconds after it was asked to end. **This is not a block:** a TCP client can connect again at once and a UDP client's next datagram starts a new session; to keep a source out, use the rule's source lists or a firewall rule set. Some connections show “—” instead of **End**: those of protocol gateways (the list shows the gateway's local bridge, whose source is a loopback address and not the real client; the client's outer TLS / QUIC connection belongs to the gateway), Shadowsocks, egress proxies, reverse tunnels, a multipath inbound whose paths use WebSocket, a SOCKS5 or HTTP CONNECT inbound inside WebSocket or multipath, and UDP sessions of rules with PROXY headers (TCP sessions of such rules can be ended). An HTTP/2 CONNECT connection ends as a whole, with all of its tunnels. The server's agent must be of this release; otherwise the dialog asks you to upgrade it. Every request and its answer go into the audit log.
- **What is kept:** current connections are fetched when you look and never stored. Blocked connections are kept in their own file beside the panel's database (`blocks.sqlite`), so they survive a panel restart: each entry for 30 days after its latest change and at most 10000 per server by default, the longest unchanged going first (an administrator can change both with `--block-record-days` and `--block-records-per-node`, or `block_record_days` and `block_records_per_node` in the installer's `controller.json`). The file is not part of panel backups: losing it loses only these records. If the panel cannot use the file (for example it was copied back readable by others), it keeps running without blocked connections, says so in the dialog and in its log, and current connections and **End** still work. The server's dialog shows 200 at a time; **Load older records** shows the next 200.
- **Older agents:** the server needs the agent of this release; otherwise the dialog says “This server's agent is too old to keep current connections and blocked connections; upgrade the agent first”, and still shows the counters. An offline server, or one that does not answer within 30 seconds, is reported as such. Older agents keep forwarding as before.
- **Not included:** samples of probe or scanner traffic. Connections refused by a firewall rule set appear in the block records with their own reason. A protocol gateway's connections show the local bridge address as the client and cannot be ended from the panel; its firewall refusals appear in the block records like any other.

See [Connections and blocked connections](CONNECTIONS.md) (Chinese) for the details.

### Upgrades and rollback

Build and sign the new version with the same key, copy it to each server, then upgrade the **panel first**:

```sh
cd /root/relay-install; V=0.142.0
python3 scripts/relay_deploy.py stop --role controller
python3 scripts/relay_deploy.py install --role controller --config controller.json \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py start --role controller
```

Set `V` to the version you are installing. Then upgrade **each server**, one at a time, with the same commands using `--role agent --config agent.json` and no token. While a server is stopped its rules carry no traffic. While the panel is stopped, servers in availability-first mode keep forwarding.

To go back, stop the role, run `python3 scripts/relay_deploy.py rollback --role controller` (or `--role agent`), then start it. Rollback switches only the program, never the data, and the installer refuses a rollback across incompatible state versions. When rolling back across a release that changed what agents report, roll the agents back before the panel. Check release notes before rolling back: for example, subscriptions with chained proxies must be deleted before going back to 0.141.5 or earlier, and server locations must be cleared before going back to 0.127.x. See [Linux deployment](LINUX_DEPLOYMENT.md).

### Backup and restore

The panel's state is the folder `/var/lib/relay-platform/controller/`. The simplest consistent backup stops the panel for a moment:

```sh
cd /root/relay-install
umask 077; install -d -m 700 /root/relay-backups
python3 scripts/relay_deploy.py stop --role controller
tar -C /var/lib/relay-platform -czf /root/relay-backups/controller-$(date +%F).tar.gz controller
python3 scripts/relay_deploy.py start --role controller
```

Copy the archive to another machine. It contains passwords and keys, so keep it private.

- Servers in availability-first mode keep forwarding during the backup. Strict-lease servers stop after about 25 seconds, so keep the stop short.
- The panel also writes a continuous **recovery log**. A backup made with `relay backup` while the panel runs, plus the complete log, can rebuild everything committed after the backup with `relay restore`. **Recovery protection** shows the log's state. See [Recovery](RECOVERY.md).
- `recovery.log` grows over time, by hundreds of MB per week on a busy panel. Leave free disk space and never delete or shorten it by hand.
- Each server's identity lives in `/var/lib/relay-platform/agent/`. Back it up separately, together with any TLS certificates and keys. Losing it means enrolling a replacement identity.

### FAQ

**A new server never shows as online.**
Read `journalctl -u relay-platform-agent -n 50 --no-pager` on the server and check that `curl -sI https://panel.example.com` works from it. The node ID and token must match, and the token works only once. If it was lost or already used, delete the never-enrolled node and enroll it again.

**The server is online but clients time out.**
Relay never opens firewall ports. Check the server's firewall and the provider's security group, the rule's source lists, the quota and expiry, and that the server can reach the destination itself. A TCP test proves nothing about UDP; test UDP with the real application.

**The panel shows "Apply failed".**
The server rejected the new configuration and kept running the previous one. The message gives the reason, often a port already in use (`ss -lntp` shows which process holds it) or a missing local certificate.

**What happens when the panel is down?**
Availability-first servers keep forwarding with their last configuration. Strict-lease servers stop after about 25 seconds and resume one lease period after the panel returns. Customer traffic never passes through the panel.

**Is traffic counted once per path or once per hop?**
Once per hop. Each rule keeps its own ledger, and a budget that covers several hops counts each of them.

**Can I use ports below 1024?**
Not for forwarding by default: the agent runs as a dedicated non-root user and the installer does not grant low-port rights. Use ports above 1024. Port 53 for the authoritative DNS pool has its own permission file.

**Why does `[::]:PORT` not accept IPv4 clients?**
In Relay, `[::]:PORT` listens on IPv6 only. Create a separate IPv4 listener if you need both.

**Which client apps work with subscriptions?**
Relay generates V2Ray/Base64, Clash/mihomo, sing-box, Surge and Shadowrocket formats, and the generated files are checked automatically. Not every app and version has been tested end to end, so test the apps your customers use.

**I lost the admin password.**
On the panel server, stop the panel, set a new password, then start it again:

```sh
python3 scripts/relay_deploy.py stop --role controller
sudo -u relayp-controller /opt/relay-platform/roles/controller/current/relay reset-password \
  --state /var/lib/relay-platform/controller --user admin
python3 scripts/relay_deploy.py start --role controller
```

The new password is written to `/var/lib/relay-platform/controller/admin-password.secret` and is never printed. The command refuses to run while the panel is running, and it signs that user out everywhere and revokes their API tokens.

**Sign-in says "too many login attempts".**
Wait five minutes. The limit is 30 attempts per 5 minutes per visitor. Behind Caddy or nginx on the same server, the panel tells visitors apart by the `X-Forwarded-For` header the web server adds.

**Can I move a server's identity to a new machine?**
Use **Node identity** to revoke the old identity and issue a replacement token, then start a new agent with the same node ID in an empty state directory. Never run two copies of the same identity at once.

**Do I have to buy anything or activate Relay?**
No. Relay runs without commercial products or activation. Managed protocols use the open-source sing-box engine, which you install yourself.

### Current limits

Relay is a development release. Every one of its 22 modules is marked "partially implemented" in [STATUS.md](STATUS.md), and none has passed full acceptance. In particular:

- **Platform:** one panel with SQLite. There is no high availability, no PostgreSQL, no off-site replication or rotation of the recovery log, and no full disaster recovery. OpenRC services have not been run on real machines; systemd on Debian 13 has.
- **Performance:** published throughput figures come from loopback tests on one machine. WAN throughput, endurance and minimum hardware have not been established. Packet loss seen on some public UDP paths is still under investigation.
- **Certificates:** TLS certificates for forwarding are files you provide. Automatic issuance, renewal and revocation lists are not implemented.
- **Clients:** subscription output is checked automatically, but the full matrix of real client apps (Clash/mihomo, Surge, Shadowrocket, v2rayN and others) has not been run. Shadowsocks has one key per port, without plugins.
- **Multipath and MPTCP:** verified locally and in Linux network namespaces; real multi-link performance has not been measured. Relay's multipath protocol is its own and makes no claim of compatibility with other products' protocols.
- **DNS:** tested against a mock Cloudflare API and a mock webhook receiver; a real Cloudflare account, a real webhook receiver (including ZeroForwarder's own), DNS propagation, real port 53 and registrar delegation have not been verified.
- **WireGuard and NAT:** tested in Linux namespaces; real home routers, carrier-grade NAT, IPv6, exit nodes and subnet routes are not covered.
- **Cross-panel sharing:** not yet verified between two separate panels over the public internet.
- **Reverse tunnels:** no real public network, NAT, long-running or high-concurrency tests.
- **Routing and access control:** no GeoIP or ASN rules, no rule files from outside the panel, no protocol filters (such as BitTorrent or QUIC), and no automatic path selection by cost.
- **Accounts:** no per-object permissions and no password recovery by email.
- **Commerce:** no adapters for specific payment providers, commissions, taxes or invoices. Plans do not set speed limits or device counts.

**Feature status** in the panel lists what is implemented and what still waits for acceptance.

### Further reading

- [Deploying Relay on a new server, start to finish](DEPLOYMENT_GUIDE_EN.md)
- [Panel tutorial: servers and a first forwarding test](PANEL_TUTORIAL_EN.md)
- [Linux deployment, upgrades and rollback](LINUX_DEPLOYMENT.md) (Chinese)
- [Panel layout and handbook](UI_WORKSPACE_EN.md)
- [Multi-hop topology](TOPOLOGY.md) and [target health](HEALTH.md) (Chinese)
- [Protocol gateways](PROTOCOL_GATEWAYS.md), [MPTCP](MPTCP.md), [WireGuard](WIREGUARD.md), [cross-panel sharing](FEDERATION.md)
- [API reference](API.md) (Chinese)
- [Module status](STATUS.md) (Chinese)
