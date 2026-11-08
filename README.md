# Relay 独立转发平台

**Setting up a new server?** Follow [Deploying Relay on a new server, start to finish](docs/DEPLOYMENT_GUIDE_EN.md): build and sign a package, install the panel, add HTTPS, sign in, add nodes, upgrade and back up.

0.150.0 adds named firewall rule sets. Under Forwarding setup → Firewall rule sets, a set is a named list of allow and deny rules by source, destination and port, checked from the top so the first match decides, plus a default action for anything no rule matches. System administrators bind an inbound and an outbound set to a server, in its settings or with Bind…; tenant administrators bind their own inbound sets to their own rules in the rule editor. A connection has to pass every set that applies plus the rule's own lists, so a set can only make a rule stricter. Outbound sets are checked before the server connects to fixed targets, to the destinations that SOCKS5, HTTP CONNECT, HTTP/2 CONNECT and Shadowsocks clients ask for, and to egress proxy upstreams; reverse tunnels, protocol gateways and the agent's own traffic are not covered. Edits reach servers without republishing, Server policies shows whether each server has applied them, the Rule tester shows which rule of which set decides for an address, and refusals appear in the blocked-connection records. Two changes affect existing rules: `*.example.com` in destination lists no longer matches look-alikes such as `badexample.com`, in deny lists too, and the first UDP packet of a SOCKS5 association must come from an address the rule accepts. Rule sets need the 0.150.0 agent: until a server's agent has reported in, the panel refuses them there with "upgrade it first", while servers without rule sets keep working with older agents. Don't downgrade the agent on a server that uses rule sets: in tests, the 0.149.0 agent would not start when a rule had a set, and ignored server-level sets otherwise. See [Firewall rule sets](docs/FIREWALL.md).

0.149.0 adds egress proxies: a proxy rule can reach its destinations through an upstream SOCKS5 proxy instead of connecting to them directly. In the rule editor, when a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks proxy service is enabled, the Egress proxy section takes up to 8 upstream addresses (host:port, one per line, tried in order when one cannot be reached), an optional upstream username and password, and Import link for socks5:// links. The client's destination still comes from its request, and allowed and denied destinations are checked before the upstream is used. Egress proxies carry TCP only: UDP is refused for these rules, never sent around the upstream. By default the server looks up domain names itself and sends addresses to the upstream. Metering, quotas, budgets and speed limits are unchanged, and the rules table and the Connections dialog show the upstream. Hysteria2, TUIC and Juicity upstreams and using another rule as the upstream are not supported yet. Egress proxies need the 0.149.0 agent on the server: until its agent has reported in, the panel refuses them there with "upgrade it first", while rules without an egress proxy keep working with older agents. See [Egress proxies](docs/EGRESS_PROXY.md).

0.148.0 adds speed tests, live connections and blocked-connection records, protocol gateways in more subscription formats, and DNS webhook providers. Under Diagnostics, system administrators can run a Speed test from a server to Cloudflare's speed service or to another server, and Path speed test… on a rule (for anyone who can edit every server on its path) measures each segment, shows the slowest one and the target's connect time; test traffic is neither limited nor counted. Connections… on a rule shows its live TCP and UDP sessions with client, target and bytes, plus its counters, and Blocked connections under Forwarding rules → By server lists refused connections with the reason and a count. Speed tests and connection lists need the 0.148.0 agent on the servers involved; older agents keep forwarding and the panel says to upgrade them. Surge subscriptions now include the VMess, Trojan, TUIC v5, Hysteria2 and AnyTLS gateways, and V2Ray and Shadowrocket subscriptions include the same gateways except AnyTLS. DNS management can also push records to a DNS webhook, a receiver you run that checks signed requests, following ZeroForwarder's public description of its DNS Webhook protocol; it has not been tested against ZeroForwarder's own receiver. Delete DNS webhook providers before moving the panel back to 0.147.0 or earlier. See [Speed tests](docs/SPEED_TESTS.md), [Connections](docs/CONNECTIONS.md) and [DNS](docs/DNS.md).

0.147.0 adds separate upload and download speed limits and burst limits. Every speed limit (a rule's rate in the rule editor, Node rate limit under Forwarding rules → By server, and a user's Total rate limit under Users & permissions) now has a Limit mode: Combined upload and download (as before), Separate upload and download, or Combined and separate. Rules and servers can also allow a burst: a faster burst rate for a burst time, after which the limit applies; for example a burst of 100 Mbit/s for 300 seconds over a 30 Mbit/s limit, with the burst earned back while traffic stays below the limit. The rules table shows every limit and how much burst credit is left. Separate and burst limits need the 0.147.0 agent on each server involved: until a server's agent has reported in, the panel refuses them there with "upgrade it first", while combined limits keep working with older agents. Metering, quotas and budgets are unchanged.

0.146.0 adds traffic reset cycles and automatic top-up for plans. In the plan editor (Wallet & orders), Traffic reset can be No reset (the default and the old behaviour), Follows the billing period, or Every N days. Each cycle starts again with the plan's traffic; unused traffic does not carry over, and usage history is never rewritten. A plan can also offer a top-up: a fixed amount of traffic at a fixed price, with a cap per cycle. When a user switches on Automatic top-up under My plan and the cycle is about to run out, the wallet is charged once and a Top-up order appears; if it cannot run (switched off, cap reached, not enough balance) the reason is shown and nothing is charged. My plan shows usage, remaining traffic and the next reset for the current cycle, and system administrators can use Reset traffic now under Plan entitlements. Plans without a reset policy behave exactly as before, and agents need no upgrade for this feature. Top-up orders cannot be refunded, and a user with an active plan cannot buy a plan that resets differently until it ends.

0.145.0 adds Reverse tunnels for servers behind NAT or a home router that cannot accept inbound connections. Under Reverse tunnels (NAT traversal) on the All forwarding page, New reverse tunnel asks for a public server, a private server, a public port (Auto picks a free one in the public server's forwarding range), the target as the private server sees it, such as 127.0.0.1:8080 or a LAN address, and TCP, UDP or both. The private server's agent connects out to the public server's tunnel port (29123 by default, shared by every tunnel on that server) over TLS 1.3, checks the public agent's own key and proves itself with a per-tunnel secret that the panel never shows; one connection carries every tunnel between the two servers and reconnects on its own. Users connect to the public port, which is an ordinary forwarding rule, so usage counting, allowed and denied sources, the speed limit and the connection limit apply, and Access & limits edits them. Each tunnel shows Connected, Waiting, Error or Disabled with the reason, its entry address with Copy, and its traffic. Both servers need this version's agent; older agents receive nothing and the panel says the agent is too old. Delete a server's tunnels before moving its agent back to an older version, and open both the public port and the tunnel port in the public server's firewall. The reverse-mux commands remain as the manual option. See [Reverse tunnels](docs/REVERSE_TUNNELS.md).

0.144.0 adds endpoint groups and saved chains for multi-hop forwarding. An endpoint group is a named list of up to 32 servers that act as one layer of alternatives: the previous hop picks one of them with that layer's balancing mode, and traffic does not pass through them one after another. A saved chain puts up to 6 groups in order, each with its own balancing mode, for example HK IX → Global exits. Both are managed under Endpoint groups & chains on the forwarding page. In New forwarding, Use a saved chain asks for the entry server, a name, the protocol, the target and an optional entry port, shows the whole path for review, and then gives the entry and every server of every layer an ordinary rule that targets all servers of the next layer, published together or not at all. A chain lists the forwardings built from it. When a group's members change later, the chain shows Group members changed with the servers added and removed, and the forwarding keeps its old servers until you build it again from the chain. Chains build plain TCP and UDP hops only, and servers need no upgrade. See [Endpoint groups and saved chains](docs/CHAINS.md).

0.143.0 adds Shared rules: one forwarding rule kept on up to 32 entry servers with the same listen port, and created, edited, paused and deleted once. On the forwarding pages, New shared rule asks for a name, the servers and a port. Auto pick finds a port that is free on every selected server and inside each server's forwarding port range. Check shows each server's state, whether the port is free and in range, and whether the settings are valid. Nothing is reserved until you save, and every save publishes all servers together or none. Extend to several lines… turns an existing rule into a shared rule and copies it to more servers with the same port. The Shared rules list shows each line's status and entry address, with Copy all for customers. If one line was changed on its own, it shows Lines differ, and the next save brings it back in line. Pause, Resume and Delete act on every line, and Delete can keep the rules as ordinary rules instead. Changing the shared port restarts each line's counters. Each line is still an ordinary rule, so servers need no upgrade. Rules with a port range and built-in proxy protocols cannot be shared yet. See [Shared rules](docs/SHARED_RULES.md).

0.142.0 adds the first batch of features that a comparison with Zero Forwarder found missing, plus a single [Relay documentation](docs/WEBSITE_GUIDE_EN.md) page for the website: what Relay is, installation, every panel feature, common deployments and troubleshooting. A forwarding target can now be paused, either until resumed or until a set time; a paused target takes no new sessions while existing ones continue. The new Random balancing mode spreads new connections evenly across the preferred priority. DNS management now checks every zone automatically every 30 seconds, so health-gated records leave DNS and come back without pressing Sync now. A zone's Confirmation window waits for a failure or recovery to last before acting, and removals pause when more than half of a name's values fail at once. Providers have a connection test, a Minimum TTL setting and Load provider zones, which fills in the zone ID; each record shows its status and the reason. A server that cannot reach the panel directly can list up to 8 controller addresses to try in order, or use an HTTP proxy, with TLS still checked end to end. `relay reset-password` resets a forgotten password on the server while the controller is stopped. Subscriptions can be edited without changing the link, they tell proxy apps their usage and expiry, and they can be limited to allowed fetch sources. Rotate subscription link can keep the old link working for up to 24 hours. Hysteria2 gains obfuscation and a fixed masquerade response. TUIC gains a congestion-control choice and 0-RTT, and Reality takes several short IDs and a clock-difference limit. VLESS, VMess, Trojan, Hysteria2 and TUIC rules get a share link with a QR code. Alert rules adds node CPU and memory, node expiry, a shared budget near its limit or exhausted, and DNS record sync failures, each with its own threshold. WireGuard networks can give devices DNS servers, and each device can have its own AllowedIPs and keepalive, an on/off switch and an optional preshared key.

0.141.9 makes deleting easy to find. A node's details now end with a red Delete node section: a node still bound to an Agent identity offers Revoke identity and delete…, which opens the emergency revocation form and then the delete confirmation, and other nodes offer Delete node…. Every forwarding on All forwarding has a Delete button. A forwarding that crosses servers is deleted in two steps, because the panel only removes chained rules once their servers have stopped them: the first Delete stops the whole route without changing it, and pressing Delete again after the servers confirm removes its rules; hops that other forwarding also uses are kept. If a server has not confirmed, the panel says so, and for a server that is offline points to deleting that node instead. On By server, Delete on a forwarding's entry rule runs the same steps, and on a middle hop explains that the whole forwarding must be deleted and opens All forwarding.

0.141.8 rebuilds the Overview around what an operator checks first. Each summary card now shows a bar sparkline in its own color and how the live value compares with the same hour yesterday (from the 7-day history; round trips are green when faster and amber when slower). A new row puts a 24-hour connection dial beside what needs attention: the dial draws one spoke per 15 minutes of local time, with teal dots for real connections to targets that succeeded and red dots for failures, and the success rate in the middle. Needs attention shows the newest unresolved problem with buttons to open the node or the event list (green when nothing is open), then each node's traffic over the selected range. A throughput chart with a dashed line for the same time yesterday sits under it. The globe, events, forwarding paths, trends and node table follow as before; the separate throughput trend moved into the new card.

0.141.7 makes the Surge subscription a complete profile that Surge installs and keeps up to date. The public link now starts with #!MANAGED-CONFIG pointing back at itself (from the forwarded host and X-Forwarded-Proto), so Surge refreshes it daily, and the profile adds a [General] section (system DNS, local addresses bypass the proxy, connectivity test URLs), Auto (fastest relay entry) and Fallback (first working entry) groups, and rules for Surge's Rule-based mode: Apple system services and the local network go direct, mainland China goes through a Mainland China group that defaults to direct, and everything else ends at FINAL,Relay,dns-failed. This replaces the Clash-style MATCH,Relay line, which Surge does not document. Existing Surge links get the new profile on their next fetch; see [Client subscriptions](docs/SUBSCRIPTIONS.md).

0.141.6 lets a subscription chain your own proxy. Add up to 8 SOCKS5 or Shadowsocks proxies when you create a subscription, by hand or by pasting a socks5:// or ss:// link, and the sing-box, mihomo / Clash Meta and Surge formats export each one as an entry the app reaches through a relay node: app → relay node → your proxy → website. The app builds the chain itself (sing-box detour, mihomo dialer-proxy, Surge underlying-proxy) from a new Relay entry group, so node configuration is unchanged. V2Ray and Shadowrocket cannot express a chain and list these proxies as skipped. A mistake in the subscription settings now returns a clear 400 message instead of an internal error. Before rolling back to 0.141.5 or earlier, delete subscriptions that contain proxies; see [Client subscriptions](docs/SUBSCRIPTIONS.md).

0.141.5 replaces the flat grey page of the light theme with a near-white canvas and a faint mist of the companion colors (teal top left, violet top right, pink lower right). The page, sidebar and page header share one background fixed to the window, so there is no seam between them, and white cards keep a thin cool border and soft shadow. The mist stays faint enough that every sidebar and header text color keeps 4.5:1 or better. The dark theme is unchanged.

0.141.4 adds companion colors. Teal, blue, violet and pink tell summary-card icons, sidebar sections and chart series apart (download is now violet beside teal upload), and each card on a page gets a soft wash of color at the top of its heading that fades to the plain card, starting from the color of the page's sidebar section. Appearance has a new Card color slider: 0 turns the wash off, and its strongest setting still keeps every text color at 4.5:1 or better. The page behind Appearance is no longer blurred, so changes preview live.

0.141.3 restyles the panel after the Regline dashboard, in both themes. The sidebar and page header sit on a neutral grey page and content lives on cards; the overview metrics share one card with icon tiles; status labels are soft tinted tags; progress and status bars are striped pills; table actions are small outlined buttons. Coral is now the default accent and is kept for actions and selection: the current sidebar item and Page guide topic get a warm tint with a coral bar on the left edge. Charts use teal, blue and violet instead of the accent, and red now means only a problem, so it no longer looks like a button or ordinary traffic. Unselected time-range and chart/table options are flat instead of slightly shadowed.

0.141.2 counts sign-in attempts per visitor behind a reverse proxy. The limit is still 30 attempts per 5 minutes, but a panel behind Caddy or nginx on the same server used to count every visitor as the proxy itself, so anyone could lock everyone out for five minutes. When a request comes from this server's own loopback address, the panel now uses the last `X-Forwarded-For` entry, the one the proxy appended. It ignores earlier entries supplied by the visitor and never trusts the header from other machines.

0.141.1 makes the light theme clearer: white panels on a cool grey page instead of white on near-white, firmer borders, near-black text, darker secondary text (about 7.6:1 contrast instead of 4.6:1), white form fields and stronger status colors. The dark theme is unchanged. Appearance now offers eight accent colors: Indigo (default), Violet, Rose, Ember, Emerald, Cyan, Sky and Graphite (monochrome), each tuned separately for light and dark so text on it stays readable; healthy, warning and error keep their fixed colors.

0.141.0 rebuilds how the panel is laid out, not only its colors. The sidebar now runs the full height of the window, with search at the top and your account and sign-out at the bottom. Each page has a slim sticky bar with its title, status and controls (the overview's trend range moved there) in place of the breadcrumb, large heading and timestamp row. Editing and details open in a panel that slides in from the right; short confirmations stay centered. The overview puts the globe beside recent events, then the forwarding paths, trends and node table. The Nodes page adds All / Online / Needs attention / Awaiting enrollment tabs, and clicking a node opens its status, profile and every node task. Both themes have new colors: a blue-black dark theme with an indigo accent (default) and a warm-paper light theme with ink text and a cobalt accent. Tables, tiles, segmented controls, the handbook and the sign-in page were refined to match. Pages, data and actions are otherwise unchanged.

0.140.0 adds optional cross-panel sharing (off by default; new Cross-panel sharing page). An owner panel gives another Relay panel a port range on one of its nodes with a rule count, rule kinds (port forwarding and/or Shadowsocks 2022), bandwidth, traffic limit, expiry and source and destination limits. The receiving panel redeems a one-time invite code for its own secret and asks for rules inside the range; the owner renders every rule itself, so the receiver cannot widen the share and the owner's own publishes cannot change or overlap it. Pause disables the rules, revoke removes them from the node and stops the receiver's secret, and both sides keep the traffic statement with a warning when the owner reports less than before. See [FEDERATION.md](docs/FEDERATION.md).

0.139.0 adds optional NAT traversal for WireGuard networks (off by default; needs WireGuard networking on). Two nodes that are both behind NAT first try to connect directly ("hole punching") at the addresses their NATs show the relay, through a trial entry that carries no traffic until a handshake proves the path works. Traffic then leaves the relay; a failed attempt (for example a NAT that uses a new port for every destination) or a direct path that goes silent for 75 s puts the pair back on the relay with the reason shown, and the next attempt waits 5 minutes, doubling up to an hour. Agents switch within about a second of each other because the configuration watch now wakes them, and a controller restart keeps working direct paths. See [WIREGUARD.md](docs/WIREGUARD.md#nat-traversal-0139-optional-feature-off-by-default).

0.138.0 adds optional WireGuard networking (off by default; new WireGuard networking page). Nodes and user devices join private IPv4 networks: nodes report their own public keys and get their peers on every sync, a pair where neither node has a public endpoint goes through a relay node, and devices connect to a public entry node with a configuration and QR code shown once. Agents act only on servers that install wireguard-tools and the new relay-agent-wireguard.conf drop-in, touch only links named rwg-*, refuse ranges that overlap the server's networks or the controller, and never change default routes, firewalls or server-wide settings. See [WIREGUARD.md](docs/WIREGUARD.md).

0.137.0 adds an optional authoritative DNS pool (off by default; DNS page). Your own nodes answer DNS for a zone you delegate to them: A, AAAA, CNAME and TXT records, SOA and NS with glue, over UDP and TCP on explicit addresses only. Each value can follow a node rule's health, with a per-zone minimum that is never withdrawn. The controller sends every member its rendered answers on each sync, the agent keeps the last copy so a restart keeps answering while the controller is unreachable, and the panel shows each name server's state and the delegation records to add at your registrar. Port 53 needs the `deploy/relay-agent-dns.conf` permission drop-in on the server.

0.136.0 adds two optional features, both off by default. Budget disaster recovery (Recovery page) lets a system administrator write off the open reservations of a node run that can no longer report, refusing runs that still hold their execution lease and waiting out handover windows, and end the allowance lock an old backup leaves; unknown use always counts as consumed and every action is audited and replay-safe. MPTCP extra paths lets node settings list extra local MPTCP addresses and limits; an agent applies them only on servers that install the `deploy/relay-agent-mptcp-paths.conf` permission drop-in, touches only its own endpoints (ids 200-207), and reports what is in place.

0.135.0 adds an Optional features page (System & help) where a system administrator turns features on one by one; all start off. MPTCP rule settings and DNS health gating now appear only after their switch is on, and a switch cannot be turned off while a rule or record still uses it (controllers upgraded with such settings keep them on). New optional plan entitlements turn a paid plan order into the buyer's traffic budget: traffic adds up on renewal, days extend the expiry, an expired plan issues no new traffic, and a refund removes that order's traffic and days without clawing back what was used. Wallet & orders shows "My plan" and an administrator overview. Switches change controller validation and panel forms only, never server system settings.

0.134.0 refines the panel into two matched themes: Obsidian (dark, default) with lifted near-black cards, crisp borders and an indigo accent, and Porcelain (light) with white cards, soft shadows and a royal-blue accent. Text uses two greys, figures use the same typeface as labels, selections are solid accent tiles, and the Inter typeface (SIL OFL 1.1, Latin subset, about 94 KiB) is now built into the binary and served by the panel itself, so it looks the same on every computer; Chinese text keeps the system font. Accents are Indigo (default), Cyan, Emerald and Ember; earlier choices map to the closest one. Only styles changed.

0.133.0 redesigns the panel: a dark-first "Midnight Ops" look with graphite surfaces, an ember accent, a bold sans wordmark, monospaced figures, pill-shaped status badges and accent-highlighted selections, plus a matching light theme. Dark is now the default; the Appearance dialog offers Dark, Light or System and four accents (Ember, Cobalt, Violet, Emerald), and accents saved earlier map to the closest new one. Only styles changed: pages, data and actions are the same.

0.132.0 adds Live logs and Diagnostics for system administrators. Every process keeps its latest 2000 log lines in memory; agents send new lines with each report once the controller asks for them, so either side can be upgraded first, and the panel follows them about every 5 seconds with source, level and text filters and a download. Diagnostics lists offline nodes, rejected configurations, hops below 90% success in the last hour with their main cause, failing probes, CPU or memory shortages and recent errors, and downloads a JSON report without passwords, keys or tokens. `GET /api/v1/logs` and `GET /api/v1/diagnostics/report` serve the same data.

0.131.0 counts real TCP connections on every hop: agents report each rule's inbound setup and each dial to a target with its failure cause, and the controller keeps seven days of five-minute buckets in its own `history.sqlite`. Forwarding rules shows each arrow's success rate for the last hour, an expanded path shows a 24-hour or 7-day strip per hop with CSV export, and Overview can switch its trends to 24 hours or 7 days. `GET /api/v1/history` serves the same data to read-only tokens. Upgrade the controller before agents; roll agents back first.

0.130.0 shows each hop's health on Forwarding rules: the arrow after a server carries the latest probe of the next hop (round trip and loss, or the failure reason when it is down), paths with several targets list each one by priority with its selection role, and a server whose configuration was rejected is marked Apply failed on the path. Overview's Events panel opens with counts of problems still open, new problems and recoveries, and lists open problems first.

0.129.0 adds chart views to Target health, Traffic ledger, Shared budgets and Alerts & notifications; each page opens as charts and keeps a Table view one click away. Overview's globe explains itself when no node has a location, and a Set locations dialog saves every node's city in one step.

0.128.0 reorganizes the panel around the work: the sidebar groups Overview, Forwarding setup, Monitoring & usage, Customers & services and System & help. Overview adds a 3D globe of located nodes with lines along each rule's next hop. One New forwarding dialog covers single-server and multi-hop rules, Forwarding rules splits into All forwarding and By server, and Templates gets a New template button. Nodes can store an optional location. 0.127.x cannot list nodes while any node has one, so clear every location (Edit node → City → Not set) before rolling back.

0.127.3 makes the panel easier to read: the sidebar shows only the current page as selected, wide tables keep their row actions pinned and wrap long headers, node rules show plain protocol and balancing names, the Traffic ledger shows node names, and recovered alerts follow the selected language.

0.127.2 stops healthy agent heartbeats from growing the recovery log (status rows are rewritten only on a change or once a minute; the panel keeps showing the latest report), adds deletion of revoked or never-enrolled nodes that nothing references (`DELETE /api/v1/nodes/{node}`, audited), and shows the full signed-in account name.

0.127.1 fixes outbound MPTCP setup on Linux 6.1 when the kernel rejects `IP_BIND_ADDRESS_NO_PORT`. Source binding and strict `require` negotiation remain enforced; see [MPTCP compatibility](docs/MPTCP.md#linux-61-compatibility).

0.127.0 adds NAT-aware UDP diagnostics and an isolated DNAT/MTU acceptance probe. The observed public-path UDP losses remain under investigation; this release does not claim to repair upstream packet loss. See the [UDP investigation guide](docs/UDP_DIAGNOSTICS_EN.md).

0.126.0 added **Appearance & layout**: Light / Dark / System, four accent colors, and Expanded / Compact overview modes within the existing workspace theme. It also improves telemetry accuracy, delayed-response handling, diagram readability and keyboard access. See the [UI review and appearance guide](docs/RELEASE_0.126.0_EN.md).

0.123.0 adds guided VPS selection, reusable reachable addresses and automatic port allocation. Choose entry, optional relays and exit, then review the path before publishing. SS runs only on the selected exit. See the [guided setup guide](docs/RELEASE_0.123.0_EN.md).

0.121.0 fixes native SS UDP fragmentation defaults and adds explicit mux listener readiness with race-free CLI tests. See the [UDP compatibility and readiness guide](docs/RELEASE_0.121.0_EN.md).

0.120.0 adds live forwarding diagrams to rule creation, multi-hop setup and publish previews, with explicit VPS roles, exit-only SS placement, candidate branches and configuration checks. See the [diagram guide and verification scope](docs/FORWARDING_DIAGRAM_0.120.0_EN.md) and [panel tutorial](docs/PANEL_TUTORIAL_EN.md). The [0.119.0 forwarding verification limits](docs/RELEASE_0.119.0_EN.md) and [SS compatibility guide](docs/SS_COMPATIBILITY_0.119.0_EN.md) still apply.

这是从独立源码开始开发的控制服务、Agent 和 TCP/UDP 转发核心。原有压缩包及三个参考产品没有作为代码基础；网络、数据库、密码哈希和 TLS 实现采用公开的成熟依赖。运行不需要商业产品激活。

**当前是开发中的 0.150.0 开发版本，完整目标尚未完成。** 已经打通真实数据转发、管理 API、节点同步、持久化计量和管理界面源码。完整范围保留在 [22 个模块验收清单](docs/REQUIREMENTS.md)，逐项状态见 [STATUS.md](docs/STATUS.md)。多路径已接入本地实现，完整性能、组网、运营交易等范围仍需继续开发。

0.117.0 新增登录页与控制台 English / 中文切换，覆盖页面、编辑器、校验提示和七篇指南；保存浏览器偏好，切换时保留会话和当前页面。此前 0.116.0 重整控制台界面：分组导航、页面与指南本地搜索、七篇内嵌操作指南、浅色 / 深色主题、移动端抽屉与可分享页面链接。现有规则、协议、计量和权限流程保留，详见 [UI workspace guide](docs/UI_WORKSPACE_EN.md)。

0.115.0 接入受管 VLESS/Reality、Hysteria2、TUIC、AnyTLS、Trojan 和 VMess，支持原生计量/ACL/限速、规则 UI、模板与 sing-box/mihomo 订阅。可选 sing-box 引擎的原始源码、许可和固定校验和随源码包提供，见 [协议入口说明](docs/PROTOCOL_GATEWAYS.md)。0.114.0 已增加原生 MPTCP 传输与租户 SMTP 告警。本轮排除支付开发；完整非支付范围及尚未通过的验收仍见 [交付清单](docs/NONPAYMENT_DELIVERY.md)。

English: [complete non-payment target checklist](docs/NONPAYMENT_TARGETS_EN.md) and [0.115.0 verification and hardware report](docs/RELEASE_0.115.0.md). The older release notes below describe historical states; use the current report for supported combinations and measured limits.

GitHub 开发、自动测试、版本发布与更新流程见 [GitHub workflow guide (English)](docs/GITHUB_WORKFLOW_EN.md)。推送源码后会运行 Linux 回归检查；VPS 升级按部署文档单独执行。

0.113.0 将 HTTP/2 CONNECT 接入规则引擎、计量/配额、ACL、限速、模板和面板，支持 Bearer 摘要、mTLS、共享并发上限及可选 TCP 缓冲预算。使用说明见 [HTTP2.md](docs/HTTP2.md)；本次验收与硬件测量见 [RELEASE_0.113.0.md](docs/RELEASE_0.113.0.md)。完整产品仍在开发中。

0.40.0 增加 MPTCP 内核能力/接口/路由/端点观测（`relay mptcp-info` 与管理员诊断 API）；仅观测，不是数据面实现，见 [MPTCP.md](docs/MPTCP.md)。

0.39.0 增加 SOCKS5 UDP ASSOCIATE 本机吞吐/延迟报告：1000 个 1200 字节数据报、32 窗口、零丢失，见 [PERFORMANCE.md](docs/PERFORMANCE.md)。

0.38.0 增加规则模板库：从现有规则存为模板，按租户/全局范围管理，应用时生成新规则 ID/名称/监听/计量周期并走正常修订校验；见 [TEMPLATES.md](docs/TEMPLATES.md)。

0.37.0 补齐 SOCKS5 UDP 的规则计量与限速：载荷计入上传/下载字节，头部不计；与复用出口 socket 的路径一致。见 [SOCKS5.md](docs/SOCKS5.md)。

0.36.0 优化 SOCKS5 UDP：关联复用 IPv4/IPv6 出口 socket 与响应任务，16 个连续数据报真实回显测试；减少每包建 socket 开销。见 [SOCKS5.md](docs/SOCKS5.md)。

0.35.0 增加 SOCKS5 UDP ASSOCIATE：TCP 控制关联、UDP 头解析/来源包装、目标 ACL/私网检查、真实 UDP 回显测试；当前每数据报独立出口 socket，性能优化未完成。见 [SOCKS5.md](docs/SOCKS5.md)。

0.34.0 增加目的地 ACL：IP/CIDR/精确域名/后缀、拒绝优先、允许白名单，统一覆盖固定 TCP/UDP、Shadowsocks、SOCKS5、HTTP CONNECT、多路径和预热路径；见 [DESTINATION_ACL.md](docs/DESTINATION_ACL.md)。

0.33.0 增加并发吞吐/延迟性能报告：1/8/32 连接、UDP RTT、双向逐字节校验与账本精确对账；单连接 Relay/直连约 0.50，8/32 连接约 0.91/0.95，结果仅限本机 loopback。见 [PERFORMANCE.md](docs/PERFORMANCE.md)。

0.32.0 增加 HTTP/1.x CONNECT 入口：可选 Basic 认证、IPv4/IPv6/域名权威、默认拒绝内网、与 TLS/WS/PROXY 组合，真实 Engine 字节转发已验证；HTTP/2 CONNECT、Digest/NTLM 和真实客户端矩阵未完成。见 [HTTP_CONNECT.md](docs/HTTP_CONNECT.md)。

0.31.0 增加礼品码：管理员创建、用户兑换直接入钱包、每用户每码一次、次数/窗口/停用限制、幂等流水；测试覆盖 Store/HTTP。见 [COMMERCE.md](docs/COMMERCE.md)。

0.30.0 增加优惠码：百分比/固定折扣、最低原价、时间窗口、使用次数、启用状态；订单保存原价/折扣/优惠码/最终金额，支付与退款按折后金额。见 [COMMERCE.md](docs/COMMERCE.md)。

0.29.0 增加租户支持工单：所有者/租户管理员/系统管理员作用域、公开回复与内部备注、关闭/重开和状态流转；关闭后拒绝新消息。见 [TICKETS.md](docs/TICKETS.md)。

0.28.0 增加外部支付回调：HMAC-SHA256 验证原始请求体、支付意图、重复回调幂等、钱包支付作废待支付外部意图、外部通道禁止钱包退款；订单页显示通道和外部支付入口。具体支付网关适配仍未实现。见 [COMMERCE.md](docs/COMMERCE.md)。

0.27.0 增加套餐、单币种钱包、幂等资金流水、订单、钱包支付和退款：普通用户购买/支付，管理员管理套餐、调整钱包和退款；重复引用/支付/退款返回 409。套餐权益尚未自动发放。见 [COMMERCE.md](docs/COMMERCE.md)。

0.26.0 增加全局/租户公告：管理员发布、租户边界、生效窗口、面板展示与 API，Store/HTTP 测试覆盖可见性、未来公告、权限和删除。运营交易的钱包/订单/支付仍未实现。见 [ANNOUNCEMENTS.md](docs/ANNOUNCEMENTS.md)。

0.25.0 增加 SOCKS5 TCP CONNECT 入口：可选用户名/密码认证、默认拒绝内网目的地、可与 TLS/WS/PROXY 组合，真实 Engine 握手与字节转发已验证；UDP ASSOCIATE 明确拒绝，真实客户端矩阵未验收。见 [SOCKS5.md](docs/SOCKS5.md)。

0.24.0 增加账号生命周期：本人修改密码（保留当前会话、撤销其他会话）、管理员重置密码（撤销全部会话和 API 令牌）、账号停用/启用（撤销凭据）、账号删除（有规则/订阅时拒绝并给出原因），并接入面板。旧密码、已撤销会话和禁用账号的登录会在真实 HTTP 路由上验证。

0.23.0 在 0.22.0 DNS 托管记录基础上增加入口健康摘除：记录可绑定节点/规则，节点心跳超过 90 秒或没有 eligible healthy 目标时观察模式报告、应用模式摘除，恢复后重建；附带 `clear_health` 和面板字段。真实 Agent 端到端与 Cloudflare 传播仍未验收。

0.22.0 新增 DNS 托管记录：Cloudflare 兼容服务商、区域、A/AAAA/CNAME 托管记录、观察/应用同步、`min_keep` 保护与 DDNS 更新；服务商令牌只向系统管理员开放且读取脱敏，记录写入既有 metadata，schema v5 不变。真实 Cloudflare、DNS 传播和权威池尚未验收；健康摘除已用真实节点健康报告结构验证，但未跑真实 Agent 端到端。见 [DNS.md](docs/DNS.md)。

0.21.0 新增客户端订阅：把用户自己的 Shadowsocks 规则按 V2Ray/Base64、Clash、Surge、Shadowrocket 快照成可撤销链接，支持模板、预览、过期、轮换和公开端点限频；令牌只保存哈希，订阅状态写入既有 metadata，schema v5 不变。当前仍只覆盖 Shadowsocks 入站，普通 TCP/TLS/WS 规则会明确列为不兼容；真实客户端矩阵尚未验收。字段、格式、权限和限制见 [SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md)。

0.20.0 修复 0.19.0 源码审查发现的四项 P1、两项 P2：广告地址监听仍执行用户跨节点限速；配置激活失败保留仍在运行修订的限速份额；Shadowsocks 规则重命名或限速调整保留 TCP 重放状态；应用 schema 升至 v5、控制器/Agent 状态兼容代号升至 2，旧程序拒绝打开启用两步验证后的状态；规则编辑保存保留维护排空字段；macOS 验证路径恢复可移植并保留 Linux 专属用例。审查中的缺陷复现已改写为回归测试。

0.19.0 新增管理账号两步验证（TOTP 与一次性恢复码）和带权限范围、有效期的 API 令牌，在“账户安全”页面管理，接口见 [API.md](docs/API.md)。本版首次在 Debian 12 x86_64 上完成源码构建与全部自动化测试，并修复节点注册令牌对话框为空等界面缺陷。

0.18.0 新增[签名离线包与 Linux 部署工具](docs/LINUX_DEPLOYMENT.md)：独立验签、架构/配置预检、安装代次切换、中断恢复、保留状态的卸载与重装。真实进程在本机隔离目录验收，Linux 原生服务和正式签名发布仍待实测。

0.17.0 新增[节点身份撤销与替换](docs/NODE_IDENTITY.md)：旧凭据退役，限时令牌在全新 Agent 状态注册，接管等待旧执行窗口结束。未知消费的预留继续占用，旧规则配额周期受保护。0.16.0 的[常规凭据轮换](docs/NODE_CREDENTIALS.md)继续保留；全部 22 模块仍在开发。

## 已打通的业务链路

1. 启动控制服务，生成私有管理员密码文件，登录管理界面或调用 API。
2. 创建节点，通过一次性注册令牌绑定独立节点凭据；注册响应丢失后可幂等重试。
3. 发布带修订号的规则，Agent 先准备全部新增监听，再提交配置。端口冲突保留旧版本。
4. 执行 TCP、UDP 或双协议转发，支持 IPv4/IPv6、域名目标、加权轮询、来源 IP 哈希和最少连接。
5. 按规则执行上下行合并配额、共享速率、到期和来源 CIDR 限制。
6. 先持久化接纳字节再转发；控制服务幂等接收累计账本。离线策略允许断网重启使用最后有效配置；严格节点每次启动先取得执行租约，从备份恢复先对账再开放监听。
7. 为 TCP 入口、出口选择 TLS，支持私有 CA、服务名验证和可选双向证书认证；私钥只留在节点本地。
8. 为用户、租户和节点创建总额度，通过持久化预留在多个 Agent 上共同执行。正常空闲或停止归还剩余额度；异常重启保守保留旧预留。
9. 控制器默认记录独立恢复日志。使用数据库备份、完整日志和最新进度清单，可恢复备份之后的节点身份、配置、权限及额度记录。

0.6.0 增加端口段与固定/偏移映射、业务出口 IP/网卡绑定、按真实响应 TTL 缓存目标 DNS，以及节点内监听环路检查。端口段共用规则额度、速率与会话上限。字段、升级注意事项和支持边界见 [ROUTING.md](docs/ROUTING.md)。

0.7.0 增加 TCP PROXY v1/v2、逐包 UDP v2、CRC32C、可信代理来源、TLS 内外报头位置及通配 UDP 实际收包地址/回复源地址。管理 API、Agent、CLI 和规则表单使用相同字段，详见 [PROXY.md](docs/PROXY.md)。

0.8.0 增加 TCP 的 WS/WSS 流隧道，入口与逐目标可独立配置路径、Host、Origin，并与既有 TLS/mTLS、PROXY、额度和限速组合。公开子协议 `relay-stream-v1` 明确定义二进制数据和双向半关闭；它不等于任意 WebSocket 服务或参考产品私有隧道的兼容实现。配置、协议、边界和两跳示例见 [WEBSOCKET.md](docs/WEBSOCKET.md)。

0.9.0 增加跨节点规则引用、多跳链与多入口、协议和环路校验，以及多节点配置差异预览与事务发布。改向前需停用关联链路并等待节点确认、会话归零；控制器一次提交期望配置，各节点分别回报应用结果。页面提供链路向导、关联启停及高级批量编辑，详见 [TOPOLOGY.md](docs/TOPOLOGY.md)。

0.10.0 增加主动目标探测、TCP/UDP 独立健康状态、主备优先级、目标会话上限、故障摘除与恢复观察，以及目标健康 API 和页面。探测复用实际出口和 TLS/WS/PROXY 参数；源节点诊断流量单独统计，下游仍正常计量。配置、状态和使用边界见 [HEALTH.md](docs/HEALTH.md)。

0.11.0 修复补额已到达却错过唤醒的竞态，将同一同步回复的用量确认与额度更新合为一次事务，并增加节点计量/额度等待、控制器队列/存储耗时统计。规则预留粒度和落盘保证保持原约定；需先升级控制器再升级 Agent，详细计数口径见 [DIAGNOSTICS.md](docs/DIAGNOSTICS.md)。

0.12.0 增加独立公开的单连接多路径流协议：mTLS 子流、可选 WSS、方向权重、分片/复制、选择确认、有限重排、断路重传和精确逻辑计量，接入现有配置 API、历史、节点和规则编辑器。运行诊断显示额外复制/重传负载；有序停止即使没有待提交用量也报告最终状态。协议、示例和限制见 [MULTIPATH.md](docs/MULTIPATH.md)。它与 Linux MPTCP、原产品专有协议分别验收，不能视为完整最终版。

0.13.0 增加单控制器协调的节点执行租约：HTTP 新建节点默认严格模式，复制状态的进程等待当前持有者结束；运行凭证绑定同步、对账和额度交换。Agent 在独立期限内续租，失效后停止 TCP/UDP、探测和聚合连接。正常停机先结算，再释放所有权；已有离线节点保留原策略，租约到期不会自动退款。配置、升级顺序和限制见 [NODE_LEASES.md](docs/NODE_LEASES.md)。

0.14.0 增加严格节点的原状态额度恢复：进程崩溃后，在控制器所有权历史连续、原 Agent 状态完整时，验证原预留、补报已持久化消费，再恢复监听。备份副本不继承该资格，其他实例接替后也不复用旧预留；未知消费继续保守占额。增加分页预留明细和恢复诊断，条件与步骤见 [BUDGET_RECOVERY.md](docs/BUDGET_RECOVERY.md)。

0.15.0 增加节点用途、分组、标签、备注、精确成本记录、筛选和批量资料编辑。资料修订与转发修订分离；严格节点支持实际暂停和到期停止，断联也受已授截止期约束。约束、升级与操作见 [NODE_MANAGEMENT.md](docs/NODE_MANAGEMENT.md)。

系统管理员、租户管理员和只读用户的权限由服务端检查。配置历史、发布冲突检查、回滚发布、会话撤销、操作审计、SQLite 一致性备份均已实现基础路径。

## 构建和验证

本次构建环境为 macOS arm64、Rust/Cargo 1.99.1。包声明最低 Rust 1.89；其他工具链和 Linux 实机尚待验证。构建需要 C 编译器和 libclang，用于 SQLite Session 扩展的构建期绑定生成；运行程序不需要 libclang。Node 只用于检查浏览器脚本，Web 资源无需 npm 构建。测试还需要 Python 3，以及 PATH 中的 OpenSSL 或 LibreSSL（只在临时目录生成测试证书）。

```sh
cargo build --locked --release
rustup component add rustfmt clippy
sh scripts/verify.sh
# 可选：用真实控制器检查订阅格式与公开端点
python3 scripts/check_subscriptions.py --binary target/release/relay --output artifacts/subscription-check.json
# 可选：用 0.18.0/0.19.0 二进制核对 schema v5 降级围栏（使用本机临时状态）
python3 scripts/check_state_fence.py --new target/release/relay --old /path/to/0.19.0/relay --legacy /path/to/0.18.0/relay
```

可执行程序为 `target/release/relay`，管理界面直接编入二进制。`Cargo.lock` 固定依赖版本，第三方清单位于 [THIRD_PARTY.md](docs/THIRD_PARTY.md)。自有代码的对外发布许可尚未指定。

## 本机控制台

```sh
./target/release/relay server --listen 127.0.0.1:8080 --state ./state/controller
```

打开本机 `http://127.0.0.1:8080`，用户名 `admin`，首次密码位于 `state/controller/admin-password.secret`。密码不会打印到运行日志。数据库和初始密码文件采用私有权限；不要将运行状态目录放入源码包或公开站点。

0.5.0 默认合并短时间内到达的节点同步请求，最多等 2 ms、每批最多 16 个请求，共享一次持久化提交。队列最多保留 64 个待处理请求，满时返回 429，Agent 稍后重试。参数 `--sync-batch-size 1` 可关闭合并以做同条件对比，允许范围 1..16。每个请求单独校验、单独回滚；全部日志确认完成后才响应，额度粒度与持久化屏障保持不变。“恢复保护”页面包含本次运行的同步统计。

在“节点管理”注册节点，将一次性令牌保存为权限 0600 的文件，然后启动 Agent：

```sh
./target/release/relay agent \
  --controller http://127.0.0.1:8080 \
  --node-id 注册后得到的节点ID \
  --enrollment-token-file ./state/enrollment.secret \
  --state ./state/agent
```

新建节点默认使用 30 秒严格租约，也可在创建时显式选择离线策略。严格节点控制连接中断超过本地剩余有效期即停止转发；复制状态的新进程必须等待重新取得租约。已有节点不会自动切换策略。

成功注册后，长期凭据保存在 Agent 私有数据库中。后续启动无需再次传入注册令牌；首次注册响应丢失时，本地已持久化的待注册身份可以继续重试。

跨机器控制连接要求有效 HTTPS，可通过反向代理接入。私有 CA 使用 `--ca-certificate`；没有跳过证书验证的选项。不要把管理界面的 127.0.0.1 地址作为另一台机器的控制地址。

## 离线转发与实际探测

准备两个终端，分别启动本地回显目标与转发程序：

```sh
python3 scripts/echo_fixture.py --port 19000
```

```sh
./target/release/relay validate --config examples/standalone.json
./target/release/relay standalone --config examples/standalone.json \
  --database ./state/standalone/agent.sqlite --watch
```

第三个终端执行：

```sh
python3 scripts/probe.py --host 127.0.0.1 --port 19001
./target/release/relay usage --database ./state/standalone/agent.sqlite
```

探测分别验证 TCP 和 UDP 的回显内容，任一失败会返回非零退出码。回显目标只监听本机。修改配置时递增 `revision`；同一版本不同内容和未知字段都会被拒绝。`--watch` 每两秒检查一次配置；停止程序使用 Ctrl-C 或 SIGTERM。

## 业务 TLS

TLS 安全层独立于目标地址。入口和出口可以分别启用；启用后仅允许 TCP。一条规则不能混合明文与 TLS 出口，证书验证失败不会回退到明文。

节点本地证书目录示例：

```text
state/agent/tls/
  entrance-v1/cert.pem     # 叶证书及中间证书链
  entrance-v1/key.pem      # 匹配的 PEM 私钥，权限 0600
  trust-v1/ca.pem          # 自定义信任根
  client-v1/cert.pem       # 可选：出口客户端证书
  client-v1/key.pem        # 可选：出口客户端私钥，权限 0600
```

`relay agent` 默认读取 `STATE/tls`；可用 `--tls-directory` 明确指定。`standalone` 的自定义证书必须用此参数指定目录。证书编号只接受字母、数字、下划线和连字符；目录与证书文件必须是真实目录/文件，编号不能指定任意磁盘路径。证书目录不可由组或其他用户写入。

入口配置例如 `"inbound_tls":{"identity":"entrance-v1","client_ca":"trust-v1"}`。`client_ca:null` 不要求客户端证书；指定 CA 后只接纳该信任根下的有效客户端证书。每个目标可添加 `"tls":{"server_name":"relay.example.com","ca":"trust-v1","identity":"client-v1"}`；`ca:null` 使用随依赖固定的公共根，`identity:null` 不提交客户端证书。面板提供相应字段，不收集私钥。

TLS 1.2/1.3 使用 rustls；没有跳过证书验证或启用早期数据的配置。握手受连接超时和并发上限约束。错误证书、服务名和私钥匹配都不会静默通过。计量仍按解密后的应用负载，TLS 开销不计入当前规则额度。

更新文件后发布新修订才会加载新证书；建议使用新的证书编号。材料或 TLS 安全参数变化会终止旧会话。文件缺失、私钥权限不合规或证书与私钥不匹配时保留旧配置。自动签发、续期与吊销列表尚未实现。WS/WSS 采用相同本地证书配置，见 [WEBSOCKET.md](docs/WEBSOCKET.md)。

## 计量、限速与故障行为

- 配额单位为字节，计量口径是**已接纳的应用负载**，上下行合计；目标写入失败时也可能已计入额度。向传输流成功写入并刷出的应用字节另在节点运行统计中显示；这不等于远端应用已经收到。
- `quota_bytes: null` 为不限量，`0` 为禁止接纳；`rate_bytes_per_sec` 是每秒字节，非 Mbps，且由规则内所有会话共享。
- 速率桶允许 `max(64 KiB, 一秒额度)` 的突发。受限时，4 KiB 及以上的大块读写按到达顺序排队轮流取用额度，各连接平分速率；小于 4 KiB 的读写（交互流量、新连接最初的读取）不排队，大流量占满限速时也不会被拖慢。公平先按用户（规则所有者）再按连接：节点总限速打满时各用户轮流取用额度，一个用户开 8 条连接也只得到 1 份，同一用户的连接之间再平分；规则限速只涉及一个用户，等同于按连接平分。轮转以一次读写为单位，大块读写大小相近时近似按字节平分。跨节点用户总**流量额度**与总**速率**均已接入。
- 节点总限速是节点配置的 `rate_bytes_per_sec`（控制台“规则”页的“节点总限速”，以 Mbit/s 填写）：本节点所有规则的 TCP（含 WS/WSS、多路径）与 UDP 应用字节上下行合计共用一个速率桶，与规则自身限速同时生效。发布请求不带该字段时保留当前值，`null` 取消；回滚到历史修订时一并恢复当时的值。它不终止已有会话，下一次读写即按新速率执行；Agent 与控制器之间的管理流量和健康探测不经过该桶，所以限速再低也不会切断管理。未设置时配置中不出现该字段，旧版 Agent 照常接受；设置后需先升级控制器和 Agent。
- 跨节点用户总限速（0.19.0）：系统管理员在“用户”页给某个用户设定总速率（`PUT /api/v1/users/{id}/rate`，以 Mbit/s 填写），该用户在所有节点、所有入口规则上的上下行合计不超过它，与规则、节点限速同时生效，取较严者。只计入口：声明了 `advertise` 的规则是多跳链路的后续一跳，流量已在入口计过一次，不再计入，也不受该限制；没有用 `via` / `advertise` 声明的链路每一跳都会计入，实际可用速率会按跳数减少。控制器在每次 Agent 同步时把总速率分成各节点的份额：忙的节点（发送在等额度）不断加份额，空闲节点保留 1/(8N) 的小份额，以便新流量立即开始；份额只占用其他节点已让出的部分，所以各节点同时生效的份额之和不超过总速率。持有份额的 Agent 每秒同步一次，新份额在一到两个同步周期内生效。Agent 按发出同步请求的时刻起保留份额 15 秒；连不上控制器时降到平均份额（总速率 ÷ 节点数），控制器对 20 秒未同步的节点也只按平均份额计算，因此失联节点不会导致超限，但会一直保留这份平均份额（“用户”页的总限速对话框会标出“未连接 / 失联”的节点），直到停用该节点（需严格租约）或停用它上面该用户的规则；已停用、已到期的节点不占份额。Agent 重启后从平均份额开始，直到控制器回复。误差：每个节点的速率桶有约一秒份额的突发；修改总速率在节点下次同步时生效（没有份额的节点默认 5 秒）；控制器刚重启的 20 秒内，未同步过的节点按持有全部速率计算，其余节点可能暂时只得到极小份额。设置后需先升级控制器，再升级 Agent；旧版 Agent 不执行该限制。
- 计量周期由 `meter_epoch` 显式标识。改名称、重启、重复发布不会清零计量；重新分配周期需保留旧账。
- 未改变的规则保持连接；普通规则仅目标/均衡调整时，已有 TCP 使用原目标，新连接采用新目标。声明了拓扑端点或下一跳的规则改变路由结构时，控制器要求先停止并确认，节点也会撤销旧会话。禁用、删除、协议、WS 参数、PROXY 策略、TLS 安全策略/材料、额度、到期、限速、空闲时间或 ACL 变化会终止关联会话。普通目标调整的 UDP 会话在空闲回收前继续使用原目标。
- 更换 UDP 监听地址会取消旧监听上的会话，限速等待不能长期占用旧端口。降低连接或会话上限时，已有会话自然排空，新会话按新上限准入。
- 无法持久化计量时拒绝负载。网络断联、控制端 5xx、429 或无效 JSON 不覆盖最后有效配置；身份、账本冲突等明确拒绝会停止 Agent，要求修复状态。
- `stats` 是本次进程的实际运行计数，重启后从零开始；累计账本持久保存。控制在线和实际业务健康分别判断。

更详细的模型见 [架构决定](docs/architecture.md) 与 [API 说明](docs/API.md)。

## 跨节点共享额度

在“共享额度”中为用户、租户或节点设置字节总额与单次预留大小。引入新额度前，要先停用相关规则，并等所有相关节点确认配置；创建后重新启用规则时，控制器会自动绑定适用额度。回滚配置或编辑规则不会移除这种绑定。一个数据包要同时满足规则及所有适用层级的额度。

控制器保证“已消费 + 尚未归还的预留 ≤ 总额度”。Agent 持有独立预留，在本地事务中扣量后才转发；预留用完前申请补充。TCP 在补额期间保留尚未转发的缓冲内容，UDP 必须整包获准。单个 UDP 包大于预留批次时可请求至少容纳该包的额度，仍受剩余总额约束。

进程持续运行但控制器断联时，只能在策略允许的剩余时间内使用已有预留。0.14.0 的严格节点可在原状态完整、所有权连续且逐项验证通过后延续原预算运行；受管备份、离线节点及发生接替的旧状态会创建新运行，旧的未知预留继续保守占额。正常情况下，业务会话全部空闲或有序停止时封存并归还已知未用部分。周期重置、未知消费的权威恢复和完整灾难恢复仍待实现，详见 [BUDGETS.md](docs/BUDGETS.md)。

## 备份与部署范围

```sh
./target/release/relay backup --database ./state/controller/controller.sqlite \
  --output ./backups/controller.sqlite
```

备份使用 SQLite 在线备份接口，不覆盖已有文件。控制数据库含用户、节点凭据哈希、配置历史和上报账本；Agent 数据库含节点长期凭据、最后配置及本地计量，必须分别保护。备份工具会在导出的受管 Agent 数据库中设置恢复标记并移除原预算运行续接资格，不改变正在运行的数据库。恢复文件后首次启动先逐页对账，将已确认累计值作为下限；断网、分页中断或新配置应用失败时均不开启旧监听。已确认离线策略的普通状态库重启可按原约定断网运行；严格节点必须在线取得租约，恢复预留时还必须完成验证。控制器进程身份变化会让在线 Agent 重新核对确认位置，补报被旧控制器快照遗忘的数据。

恢复 Agent 时先停止旧实例，将工具产生的节点备份放进新的私有状态目录，使用原节点 ID 和控制器地址启动；证书、CA、私钥目录须另行保管和恢复，SQLite 备份不包含它们。同一路径有实例锁，但跨机器复制出的同一身份不能靠本地锁互斥。不要同时运行原 Agent 与恢复副本。

0.4.0 的控制器默认在 `STATE/recovery.log` 记录数据库变更，并维护 `recovery.log.head.json`。可以用 `server --recovery-log` 将日志写在已创建的另一个私有目录；自动异地复制与日志轮换尚未实现。只有旧数据库备份会缺少之后已发放的额度，因此导出文件仍带分配隔离标记，不能直接清除。

停止原控制器后，使用启用日志之后生成的备份及最新完整日志恢复：

```sh
./target/release/relay restore --backup ./backups/controller.sqlite \
  --recovery-log ./state/controller/recovery.log --output ./state/restored-controller
./target/release/relay server --state ./state/restored-controller --listen 127.0.0.1:8080
```

输出目录必须尚不存在；日志相邻的最新 `.head.json` 必须一起保留。命令校验连续性并重放变更，成功后恢复原控制器的额度分配状态，原备份和日志不变。管理页面“恢复保护”显示日志状态；发生日志写入故障会停止后续写入，健康检查返回 503。完整步骤及失败处理见 [RECOVERY.md](docs/RECOVERY.md)。

恢复只能使用仍然保存的数据；尚未上报且已从节点磁盘丢失的数据无法凭空重建。哈希链不能证明同时回退的日志及进度清单是最新版本。节点执行租约已有单控制器实现；异常预留恢复、双端数据同时丢失、密钥迁机和异地存储仍待完善，不能称为完整灾难恢复。

`deploy/` 提供 systemd 和 Caddy 配置模板，**尚未在 Linux 实机验收**，没有在你的机器安装服务或修改网络配置。控制服务模板使用 DynamicUser；Agent 模板需要先创建独立的 `relay-agent` 系统用户与组，将注册文件设为该用户可读的 0600 文件。默认使用 1024 以上业务端口，不赋予节点任意 shell 执行或 root 网络管理能力。

0.4.0 会把状态库迁移到 schema v4，增加恢复检查点和已取消预留请求记录；v1/v2/v3 数据可迁移。受管 v1 节点第一次升级仍需要控制器在线。控制器和 Agent 需要协调升级：0.4.0 扩展了严格校验的额度同步字段，与 0.3.0 混用会被拒绝。迁移前保留旧备份；旧二进制拒绝 v4 数据库，不能直接降级。升级前的控制器备份没有连续恢复日志，不能使用新日志恢复；升级后应生成新的基线备份。

SQLite 版本限定单控制实例。0.18.0 提供签名离线部署工具和 OpenRC/systemd 服务生成；原生服务、正式 Linux 签名发布、PostgreSQL、控制面高可用及完整恢复仍待验收或实现。

0.5.0 继续使用 schema v4 和 0.4.0 的节点同步字段、日志格式，现有 v4 日志可以继续使用。合并提交改变的是一次数据库事务包含的节点请求数量，不改变日志的确认顺序。

## 性能数据

```sh
python3 scripts/bench_loopback.py --mib 32 --rounds 5 \
  --output ./artifacts/benchmark.json
```

基准交替测量直连和转发，逐字节检查 TCP/UDP 回显，结束时核对持久化账本。当前结果见 [benchmark-local.json](docs/benchmark-local.json)，边界和验收记录见 [VALIDATION.md](docs/VALIDATION.md)。这是无 TLS 的本机回环烟测，不能推导实际线路吞吐，也没有证明优于 Realm 或另外两个参考产品。

另外可运行 `python3 scripts/bench_budget.py --output artifacts/benchmark-budget.json`，在两个实际 Agent 进程间比较启用共享额度前后的吞吐，并核对控制端、Agent、总额度三份计量以及有序停止后的预留归还。它仍是本机回环测试。

WS/WSS 的独立互通脚本为 `scripts/check_websocket_interop.py`，原生两跳对比基准为 `scripts/bench_websocket.py`；在独立 Python 虚拟环境中安装 `scripts/requirements-interop.txt` 后运行。后者对照直连与两条计量规则构成的 TCP、WS、双向证书 WSS，逐轮轮换执行顺序，核对原账本和备份。它不等于真实两机或广域网结果。

`scripts/check_topology.py` 运行临时控制器与三个独立 Agent 进程，覆盖三种链路、停止后反转、逐跳账本和完整拓扑恢复。沿用上述独立 Python 环境，结果写入 `--output` 指定文件；这是本机多进程验收。

0.4.0 新增严格控制器恢复日志后，小批次补额出现显著吞吐回退。本机 4 MiB 预留、8 总连接约 0.32 Gbps，32 MiB 预留约 2.97 Gbps；历史条件见 [0.4.0 验证](docs/VALIDATION-0.4.0.md)。合并提交已经实现，补额调度与稳定性继续优化，此开发版尚未达到最终性能目标。

0.5.0 已加入合并提交：同一二进制、4 MiB 预留、8 总连接，关闭合并约 0.322 Gbps，默认合并约 1.277 Gbps；32 MiB 预留约 4.412 Gbps。32 个模拟节点的控制 API 中位处理率为 342.1 请求/秒，关闭合并为 52.8。这些是 [0.5.0 历史结果](docs/VALIDATION-0.5.0.md)，控制 API 与实际转发为不同基准，均不代表 Linux/WAN。可用 `python3 scripts/bench_sync.py --output artifacts/benchmark-control-sync.json` 重跑控制面交替对比；当前版本及慢样本详见 [本轮验证](docs/VALIDATION.md)。

管理页面的 HTML、JS 和 API 已实现；本次浏览器地址访问未获授权，视觉及点击验收未完成。
