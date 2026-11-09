# Deploying Relay on a new server, start to finish

This guide takes you from an empty server to a working panel with forwarding nodes. It follows the same steps used for the project's own servers, in order:

1. [Prepare](#1-prepare) a server, a domain name and a build machine.
2. [Build and sign](#2-build-and-sign-a-release-package) a release package.
3. [Copy the files](#3-copy-the-files-to-the-panel-server) to the panel server.
4. [Install the panel](#4-install-the-panel).
5. [Give the panel a web address with HTTPS](#5-give-the-panel-a-web-address-with-https).
6. [Sign in](#6-sign-in-for-the-first-time) for the first time.
7. [Add each forwarding server](#7-add-a-forwarding-server-node) (node).
8. [Create a first forwarding rule](#8-create-a-first-forwarding-rule).
9. Later: [upgrades](#upgrading-to-a-new-version), [backups](#backups) and [troubleshooting](#troubleshooting).

```text
Build machine --(signed package)--> Panel server:  panel (controller) + HTTPS web server
                                 \-> Node servers: agent, connects to the panel over HTTPS

Browser --HTTPS--> panel        Client --> node --> destination
```

- **Panel (controller):** the web interface. It stores users, nodes, rules and usage.
- **Node (agent):** the program on each forwarding server. It opens the rule ports and forwards traffic.
- **Signed package:** one file holding the program, signed with your private key. Every server checks the signature before installing, so a damaged or altered package is refused.

All commands run as `root` in Bash on Debian or Ubuntu. Replace `panel.example.com`, the version and the IDs with your own values.

## 1. Prepare

You need:

- **A panel server:** Debian 12/13 or Ubuntu 24.04 on x86_64 or ARM64, using systemd, with root access. The panel itself needs few resources.
- **A domain name for the panel,** such as `panel.example.com`, with a DNS `A` record (and `AAAA` for IPv6) pointing at the panel server's public IP. Nodes on other servers only connect to a panel over HTTPS, so this is required as soon as you add a remote node.
- **One or more node servers** with the same requirements. The panel server can also be a node.
- **A build machine:** a Linux computer with at least 4 GB of memory and the same CPU type (x86_64 or ARM64) as your servers. Use the same Linux release as your servers, or an older one: a program built on a newer release may not start on an older one. The build machine can be one of the servers, but the private signing key must never be copied to a server you don't control.

## 2. Build and sign a release package

Do this on the build machine, once per version.

Install the build tools and download the source of the version you want:

```sh
apt-get update
apt-get install --yes git curl ca-certificates build-essential pkg-config clang libclang-dev openssl python3

V=0.141.1
git clone --branch "v$V" --depth 1 https://github.com/EntropyEnthalpy-SYS/relay-platform.git /root/relay-build-$V
cd /root/relay-build-$V
```

Install Rust if it is missing ([official instructions](https://rust-lang.org/tools/install/)), then build with the same Rust version the project's CI uses:

```sh
. "$HOME/.cargo/env"
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 build --locked --release --bin relay --jobs 2
./target/release/relay build-info
```

**Only the first time:** create your signing key pair:

```sh
python3 scripts/relay_deploy.py keygen --directory /root/relay-signing
```

This creates `signing-private.pem` (secret, stays on the build machine) and `signing-public.pem` (copied to every server). Back up the private key somewhere safe and offline. Packages for upgrades must be signed with the same key. If you lose it, every server has to be given a new public key.

Sign the build into a package:

```sh
python3 scripts/relay_deploy.py pack \
  --binary target/release/relay \
  --signing-key /root/relay-signing/signing-private.pem \
  --source-revision "$(git rev-parse HEAD)" \
  --output /root/relay-linux-$V.tar.gz
```

## 3. Copy the files to the panel server

Each server needs four things in one folder: the package, the public key, and the `scripts/relay_deploy.py` installer together with its `scripts/deployment/` folder. From the build machine:

```sh
SERVER=203.0.113.10   # the panel server's IP
ssh root@$SERVER 'install -d -m 700 /root/relay-install'
scp /root/relay-linux-$V.tar.gz /root/relay-signing/signing-public.pem root@$SERVER:/root/relay-install/
scp -r /root/relay-build-$V/scripts root@$SERVER:/root/relay-install/
```

On the server, make sure Python 3 and OpenSSL are present (Debian and Ubuntu usually have them):

```sh
apt-get update && apt-get install --yes python3 openssl ca-certificates curl
```

## 4. Install the panel

On the panel server:

```sh
cd /root/relay-install
V=0.141.1
echo '{"listen":"127.0.0.1:18090","behind_tls_proxy":false}' > controller.json
```

`controller.json` makes the panel listen only inside the server, on port 18090. The HTTPS web server from step 5 is the only thing reachable from the internet. (`behind_tls_proxy` only has to be `true` if you make the panel listen on a non-local address, which this guide does not do.)

Check first. These two commands change nothing:

```sh
python3 scripts/relay_deploy.py verify --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py preflight --role controller --config controller.json \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
```

Continue only when preflight shows `"ready": true`. Otherwise fix the listed `errors` first. A common one is port 18090 already being in use; pick another port in `controller.json` and in step 5.

Install, start, and make it start on every boot:

```sh
python3 scripts/relay_deploy.py install --role controller --config controller.json \
  --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
python3 scripts/relay_deploy.py start --role controller
python3 scripts/relay_deploy.py enable --role controller

curl -s http://127.0.0.1:18090/ | head -c 200   # should print the start of the panel's HTML page
```

What this sets up:

| What | Where |
| --- | --- |
| Service | `relay-platform-controller.service`, running as the dedicated user `relayp-controller`; restarts automatically if it stops |
| Program | `/opt/relay-platform/roles/controller/current/relay` (earlier versions are kept for rollback) |
| Data | `/var/lib/relay-platform/controller/` (database, recovery log, first admin password) |

## 5. Give the panel a web address with HTTPS

Put a web server in front of the panel. It holds the HTTPS certificate and passes requests to `127.0.0.1:18090`. First check that `panel.example.com` already points at this server (`getent hosts panel.example.com` should print its IP).

### Option A — Caddy (recommended)

Caddy gets and renews certificates from Let's Encrypt by itself:

```sh
apt-get install --yes caddy
cat > /etc/caddy/Caddyfile <<'EOF'
panel.example.com {
    reverse_proxy 127.0.0.1:18090
}
EOF
systemctl reload caddy
```

### Option B — nginx and certbot

Use this if the server already runs nginx for other sites. First serve the certificate check on port 80:

```sh
apt-get install --yes nginx certbot
install -d /var/www/relay-panel-acme
cat > /etc/nginx/conf.d/relay-panel.conf <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name panel.example.com;
    location /.well-known/acme-challenge/ { root /var/www/relay-panel-acme; }
    location / { return 301 https://$host$request_uri; }
}
EOF
nginx -t && systemctl reload nginx
certbot certonly --webroot -w /var/www/relay-panel-acme -d panel.example.com
```

Once certbot reports success, add the HTTPS part to the same file and reload:

```sh
cat >> /etc/nginx/conf.d/relay-panel.conf <<'EOF'
# At most 3 sign-in attempts per minute from each visitor (5 allowed in a burst).
limit_req_zone $binary_remote_addr zone=relay_panel_login:1m rate=3r/m;
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name panel.example.com;
    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;
    client_max_body_size 2m;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 120s;
    proxy_buffering off;
    location = /api/v1/auth/login {
        limit_req zone=relay_panel_login burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:18090;
    }
    location / { proxy_pass http://127.0.0.1:18090; }
}
EOF
nginx -t && systemctl reload nginx
```

Debian's certbot package renews certificates automatically through `certbot.timer`. To reload nginx after each renewal, add `--deploy-hook "systemctl reload nginx"` to the `certbot certonly` command above.

### Firewall

If the server uses a firewall, keep SSH open and allow web traffic. With `ufw`:

```sh
ufw allow OpenSSH
ufw allow 80,443/tcp
ufw enable
```

Never close SSH (port 22) by accident, or you lose access to the server. Port 18090 must stay closed to the internet.

## 6. Sign in for the first time

The username is `admin`. The first password is in a private file on the server:

```sh
cat /var/lib/relay-platform/controller/admin-password.secret
```

Open `https://panel.example.com`, sign in, then go to **Account security → Change password** and choose your own password.

## 7. Add a forwarding server (node)

Repeat this for every forwarding server.

**In the panel:**

1. Open **Nodes** and click **＋ Enroll node**.
2. Enter a name and, under the connection defaults, the server's public IP or hostname (no port). Keep **Availability first (recommended)** unless you need strict leases (see the [panel tutorial](PANEL_TUTORIAL_EN.md#3-register-the-vps-in-the-panel)).
3. Click **Create node**. The dialog **Node created · Save the one-time token** shows the node ID (inside the **Node startup command**) and the one-time enrollment token. Copy both before clicking **I saved the token**. The token is shown only once.

**On the node server:**

Copy the same four files to `/root/relay-install` as in [step 3](#3-copy-the-files-to-the-panel-server), then:

```sh
cd /root/relay-install
V=0.141.1
umask 077
read -r -s -p 'Paste the one-time enrollment token: ' token; printf '\n'
printf '%s\n' "$token" > enrollment.secret; unset token
cat > agent.json <<'EOF'
{"controller": "https://panel.example.com", "node_id": "PASTE_THE_NODE_ID", "poll_seconds": 5}
EOF
```

Reading the token this way keeps it out of your shell history. If the node runs on the panel server itself, use `"controller": "http://127.0.0.1:18090"` instead; plain HTTP is only accepted for a local panel.

Check, install, start and enable:

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

Within a few seconds the node shows as online in **Nodes**. The token is used only once. After enrollment, the node keeps its identity in `/var/lib/relay-platform/agent/`, and restarts or reboots don't need a new token.

### Servers that cannot reach the panel directly

Some servers cannot open a connection to the panel's address, for example in mainland China or on IX-only lines, while another server can. The node's agent can then connect through that other server without having to trust it. Add one of these to `agent.json`:

- `controller_addresses`: a list of `host:port` addresses to connect to instead of the addresses `panel.example.com` resolves to. They are tried in order: when an address refuses the TCP connection or doesn't answer within its share of the 5-second connect timeout, the agent moves on to the next one. The agent still names `panel.example.com` in TLS and checks the panel's certificate, so the relay only passes encrypted TCP along and can neither read nor change it. Host names in the list are looked up for every new connection.
- `controller_proxy`: a proxy that carries every request to the panel. TLS again runs end to end inside it, with the panel's name and certificate checked, so the proxy can neither read nor change the traffic. Three kinds are accepted:
  - `http://host:port`: an HTTP proxy that supports `CONNECT`.
  - `socks5h://host:port`: a SOCKS5 proxy that looks up `panel.example.com` itself. Use this when the server cannot resolve the panel's name, or should not ask its own DNS server.
  - `socks5://host:port`: a SOCKS5 proxy that is given an IP address. The agent looks up the panel's name on this server first and tries only the first address it gets; if the name does not resolve here, the agent stops with an error and never asks the proxy.

  SOCKS5 needs an explicit port, and SOCKS4 is not supported. A user name and password in the proxy URL are refused because they would be visible in the process list.
- `controller_proxy_credentials_file` (SOCKS5 only): the absolute path of a file holding the proxy's user name on the first line and the password on the second, each 1 to 255 bytes and together at most 234 bytes with `socks5://`, or 249 bytes less the length of the panel's host name with `socks5h://` (for `panel.example.com`, 232 bytes; 246 when the panel URL is an IPv4 address and 234 for IPv6). A non-ASCII host name counts in its ASCII `xn--` form, which is what the agent sends; with `socks5h://` and this file, write the panel URL in that form (for example `https://xn--strae-oqa.test` for `straße.test`) or the installer refuses it. Lengths count bytes, so a non-ASCII character counts two or more, and every byte, including `%`, reaches the proxy as written. The agent's SOCKS5 client cannot send a longer login, so the agent refuses one when it starts, and the installer refuses it when the file already exists. It must be a regular file owned by the agent's service account `relayp-agent` with mode `0600`, outside `/home`, `/root` and `/tmp`, which the service cannot read. If the file is missing, has the wrong owner or mode, or is malformed, the agent does not start, so that server forwards nothing until the file is fixed; the service manager keeps restarting it. The first installation creates the `relayp-agent` account, so on a new node create the file right after installing; on a node that already has the account, create it before the upgrade that adds the setting. The agent reads it when it starts, so restart the agent after changing it, and error messages name the file but never what it holds. SOCKS5 sends this login to the proxy unencrypted, so use it only where the path to the proxy is trusted. HTTP proxies can't use a login; use one that admits the server by its IP address.

Use `controller_addresses` or `controller_proxy`, not both. The agent never reads proxy environment variables such as `HTTPS_PROXY`, and it never goes around a configured proxy: while the proxy is down, the agent keeps trying through it, and a node in Availability-first mode keeps forwarding with its last configuration.

```sh
install -o relayp-agent -g relayp-agent -m 600 /dev/null /etc/relay-platform/agent-proxy.secret
printf '%s\n%s\n' 'PROXY_USER' 'PROXY_PASSWORD' > /etc/relay-platform/agent-proxy.secret
```

```json
{"controller": "https://panel.example.com", "node_id": "PASTE_THE_NODE_ID", "poll_seconds": 5,
 "controller_proxy": "socks5h://proxy.example.net:1080",
 "controller_proxy_credentials_file": "/etc/relay-platform/agent-proxy.secret"}
```

```json
{"controller": "https://panel.example.com", "node_id": "PASTE_THE_NODE_ID", "poll_seconds": 5,
 "controller_addresses": ["relay-hk.example.net:30443", "203.0.113.20:30443"]}
```

The installer turns this into `relay agent --controller https://panel.example.com --controller-address relay-hk.example.net:30443 --controller-address 203.0.113.20:30443 …`; `controller_proxy` becomes `--controller-proxy` and `controller_proxy_credentials_file` becomes `--controller-proxy-credentials-file`. A few rules:

- The `controller` URL must use a host name, not an IP address. TLS checks that name, and an IP address in the URL is dialed directly.
- If the `controller` URL contains a port, such as `https://panel.example.com:8443`, every relay must listen on that same port. Without a port in the URL, relays may use any port.
- You can add or change these settings when you upgrade a node; only `controller` and `node_id` are fixed.

**Use an existing Relay node as the relay.** Any enrolled node that reaches the panel directly can forward for the others:

1. In **Forwarding rules**, add a rule on that node: protocol **TCP**, listen on a free port such as `0.0.0.0:30443` (or on the panel URL's port if it names one), and a single target `panel.example.com:443`, the panel's public HTTPS address. Leave TLS, PROXY protocol and WebSocket off for both the rule and the target: the bytes must reach the panel's web server unchanged.
2. Under **Allowed sources**, list the addresses of the servers that will use it, so the port doesn't open your panel to everyone. Don't give the rule a quota or an expiry date that could cut off the nodes behind it.
3. Open the port in that node's firewall (and in the provider's security group).
4. Install the agent on the server behind it with `controller_addresses` set to `RELAY_NODE_ADDRESS:30443`, then check `journalctl -u relay-platform-agent -n 50 --no-pager`. The node comes online as usual.

The panel's web server sees the relay's IP address as the client address of these connections. List a second relay if you have one: while no relay is reachable, a node in Availability-first mode keeps forwarding with its last configuration but receives no changes.

## 8. Create a first forwarding rule

Create a rule on the new node in **Forwarding rules**. Then open the rule's port in the **node's** firewall; the installer never changes firewalls. New nodes pick ports from 20000–29999 by default. Sections 5–7 of the [panel tutorial](PANEL_TUTORIAL_EN.md#5-create-a-first-forwarding-test-on-one-vps) walk through a complete first test, including checking that traffic really takes the expected path.

## Upgrading to a new version

1. Build and sign the new version on the build machine ([step 2](#2-build-and-sign-a-release-package), same signing key), then copy the new package to each server's `/root/relay-install`.
2. Upgrade the **panel first:**

   ```sh
   cd /root/relay-install; V=0.142.0
   python3 scripts/relay_deploy.py stop --role controller
   python3 scripts/relay_deploy.py install --role controller --config controller.json \
     --bundle relay-linux-$V.tar.gz --trusted-key signing-public.pem
   python3 scripts/relay_deploy.py start --role controller
   ```

3. **Then each node**, with the same commands using `--role agent --config agent.json`. Leave out the token; a node keeps its identity across upgrades.

While a node is stopped, its rules don't forward traffic, so upgrade nodes one at a time. While the panel is stopped, nodes in Availability-first mode keep forwarding with their last configuration.

If the new version misbehaves, go back to the previous version with `stop`, then `python3 scripts/relay_deploy.py rollback --role controller` (or `--role agent`), then `start`. Rollback changes only the program, not the data. See [Linux deployment, upgrades and rollback](LINUX_DEPLOYMENT.md) for the full rules.

Check a role at any time with `python3 scripts/relay_deploy.py status --role controller` or `systemctl status relay-platform-controller`.

## Backups

The panel's state is the folder `/var/lib/relay-platform/controller/`. The simplest consistent backup stops the panel for a moment:

```sh
cd /root/relay-install
umask 077; install -d -m 700 /root/relay-backups
python3 scripts/relay_deploy.py stop --role controller
tar -C /var/lib/relay-platform -czf /root/relay-backups/controller-$(date +%F).tar.gz controller
python3 scripts/relay_deploy.py start --role controller
```

Then copy the archive to another machine. It contains passwords and keys, so keep it private.

- **During the backup:** nodes in Availability-first mode keep forwarding. Strict-lease nodes stop after about 25 seconds without the panel, so keep the stop short.
- **Backing up without stopping:** see [controller recovery](RECOVERY.md).
- **The recovery log grows:** `recovery.log` in that folder grows over time, by hundreds of MB per week on a busy panel. Leave free disk space, and never delete or shorten it by hand.
- **Node servers:** each node's identity lives in `/var/lib/relay-platform/agent/`. Losing it means enrolling a replacement identity ([node identity](NODE_IDENTITY.md)).

## Troubleshooting

| Problem | What to check |
| --- | --- |
| `preflight` shows `"ready": false` | Read `errors`: not running as root, port already in use, too little disk space, or a package built for a different CPU type. |
| `remote controller requires HTTPS` | `agent.json` must use `https://…`. Plain `http://` is only allowed for `127.0.0.1` or `localhost`. |
| Caddy or certbot can't get a certificate | The domain must point at this server, and ports 80 and 443 must be reachable from the internet. Check with `getent hosts panel.example.com`. |
| Node never shows as online | Run `journalctl -u relay-platform-agent -n 50 --no-pager` on the node, and check that `curl -sI https://panel.example.com` works from the node. If it doesn't, see [servers that cannot reach the panel directly](#servers-that-cannot-reach-the-panel-directly). A token works only once: if it was lost or already used, delete the never-enrolled node in the panel and enroll it again. |
| Forgot the `admin` password | Stop the panel (`python3 scripts/relay_deploy.py stop --role controller`), run `sudo -u relayp-controller /opt/relay-platform/roles/controller/current/relay reset-password --state /var/lib/relay-platform/controller --user admin`, start the panel again and sign in with the new password from `/var/lib/relay-platform/controller/admin-password.secret`. The command never prints the password and ends that user's sessions and API tokens; see [controller recovery](RECOVERY.md). |
| Sign-in says `too many login attempts` | Wait five minutes. The panel allows 30 sign-in attempts per 5 minutes from each visitor. Behind Caddy or nginx on the same server, it recognizes visitors by the `X-Forwarded-For` header the web server adds; both configurations above add it. Before 0.141.2, all visitors behind the web server shared one limit. |
| Panel page doesn't load | Run `systemctl status relay-platform-controller`, `curl -s http://127.0.0.1:18090/` on the server, and check the web server's status (`systemctl status caddy` or `nginx`). |
| A rule doesn't carry traffic | Open the rule's port in the node's firewall, and in the hosting provider's firewall or security group if it has one. |

## Related guidance

- [Panel tutorial: nodes and a first forwarding test](PANEL_TUTORIAL_EN.md)
- [Linux deployment, upgrades and rollback (detailed, Chinese)](LINUX_DEPLOYMENT.md)
- [Controller recovery and backups (Chinese)](RECOVERY.md)
- [Node identity and replacement (Chinese)](NODE_IDENTITY.md)
