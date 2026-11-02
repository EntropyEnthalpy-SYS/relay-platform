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
| Node never shows as online | Run `journalctl -u relay-platform-agent -n 50 --no-pager` on the node, and check that `curl -sI https://panel.example.com` works from the node. A token works only once: if it was lost or already used, delete the never-enrolled node in the panel and enroll it again. |
| Sign-in says `too many login attempts` | Wait five minutes. The panel allows 30 sign-in attempts per 5 minutes from each connecting address. Behind Caddy or nginx, every sign-in arrives from the web server, so all visitors share that limit. |
| Panel page doesn't load | Run `systemctl status relay-platform-controller`, `curl -s http://127.0.0.1:18090/` on the server, and check the web server's status (`systemctl status caddy` or `nginx`). |
| A rule doesn't carry traffic | Open the rule's port in the node's firewall, and in the hosting provider's firewall or security group if it has one. |

## Related guidance

- [Panel tutorial: nodes and a first forwarding test](PANEL_TUTORIAL_EN.md)
- [Linux deployment, upgrades and rollback (detailed, Chinese)](LINUX_DEPLOYMENT.md)
- [Controller recovery and backups (Chinese)](RECOVERY.md)
- [Node identity and replacement (Chinese)](NODE_IDENTITY.md)
