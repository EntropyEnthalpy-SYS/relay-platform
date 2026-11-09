# 反向隧道（NAT 穿透）：在面板中管理

反向隧道（英文界面 Reverse tunnel）用于**内网服务器在 NAT 或家庭路由器之后、无法接受入站连接**的场景：公网服务器在公网端口接受用户连接；内网服务器主动连出，与公网服务器保持一条加密的隧道连接，把每个用户连接送到它能访问的目标，例如 `127.0.0.1:8080`（内网服务器自己）或 `192.168.10.20:8080`（同一局域网的另一台机器）。两端都是面板中的 Relay 服务器（Agent），在面板中选择。它对应 Zero Forwarder 的“NAT 穿透”。

隧道协议沿用 `reverse-mux-server` / `reverse-mux-client`（见 [REVERSE.md](REVERSE.md)）的分帧、信用流控、流生命周期和 UDP 数据报，没有第二套多路复用协议；命令行工具及其参数、行为不变，仍可手工使用。

## 工作方式

- **公网端是一条普通规则。** 控制器在公网服务器上为每条隧道生成一条规则（编号 `rt-…`），监听公网端口，唯一的目标是隧道的 `target`，并带 `reverse_tunnel: <隧道 id>`。Agent 的规则引擎照常接受用户连接，只是不直接拨号目标，而是经隧道打开一条流（TCP）或一个数据报关联（UDP）。因此计量（流量账本和流量页面）、允许 / 拒绝来源、限速、最大连接数、UDP 会话上限、空闲超时等全部是这条规则自己的功能，与其他规则相同。
- **隧道连接。** 公网服务器在隧道端口（缺省 29123，与 Zero Forwarder 相同）监听隧道连接；同一台公网服务器上的全部隧道共用一个隧道端口和一个监听。内网服务器对每台公网服务器只保持**一条**隧道连接，它在这台公网服务器上的全部隧道都经这条连接承载。
- **目标由内网端决定。** 公网端打开流时只带隧道 id，内网服务器总是连接这条隧道自己的目标，只服务发给它的隧道及其允许的协议；公网服务器无法指定内网服务器连接哪里。
- **目标受内网服务器的出站防火墙规则集约束。** 内网服务器绑定了服务器出站规则集（[FIREWALL.md](FIREWALL.md)）时，它的 Agent 先解析目标，按规则集逐个判定解析出的地址，只连接允许的地址，TCP 和 UDP 都如此；全部被拒绝时不连接，并告诉公网端原因，公网端为这个用户写拦截记录（原因 `firewall`，详情以 `reverse tunnel private server: ` 开头）。修改规则集无需重新发布即生效。0.150.0 的 Agent 不做这项检查：这时新建、启用隧道或修改目标、协议、内网服务器返回 409，已有隧道照常运行，服务器状态的 `uncovered` 显示 `reverse_tunnels`。
- **断线重连。** 隧道连接断开后，内网服务器从 0.5 秒开始退避重连，每次加倍，最多 30 秒；连接稳定 10 秒后退避重置。公网端的规则在隧道断开期间照常监听，新连接会失败并很快关闭，隧道恢复后立即可用。
- **停用与删除。** 停用后公网端规则变为停用（关闭公网端口，账本保留），内网服务器在下次同步时停止为它连出；隧道端口在这台公网服务器上没有其他启用的隧道时关闭。删除隧道会删除公网端规则和令牌。控制器修改隧道时会唤醒两端的配置等待（`reverse_tunnels_changed`），两端立即同步。

## 安全

隧道连接加密，两端互相认证，令牌从不以明文在网络上出现：

- **公网服务器的密钥。** 公网服务器的 Agent 在第一次成为公网端时自己生成 Ed25519 密钥和自签名证书，私钥只保存在 Agent 的私有状态（`agent_reverse_tunnel_key`），从不离开这台服务器；Agent 只在统计中回报证书的 SHA-256 指纹，与 WireGuard 回报公钥的方式相同。隧道监听只接受 TLS 1.3。
- **钉住指纹。** 内网服务器用 TLS 连接隧道端口，只校验证书指纹是否等于公网服务器回报的指纹（不使用 CA，也不信任主机名）。指纹不符时握手失败，内网服务器回报“公网服务器的密钥与其回报的指纹不符”。
- **每条隧道的令牌。** 控制器为每条隧道生成随机 32 字节令牌（64 位十六进制），与 WireGuard 预共享密钥（`wg_psk:*`）一样单独存放在 `reverse_tunnel_token:<id>`。它不出现在任何视图、API 响应和审计记录中，只随同步发给这条隧道的两台服务器。TLS 握手之后，内网服务器发送 `REVERSE-MUX-MANAGED 1`，再为每条隧道发送 ATTACH（`<隧道 id> <令牌>`），公网服务器以常量时间比较令牌后回答 ATTACHED 或 REFUSED（“unknown tunnel”“token rejected”）。连接 10 秒内没有附加任何隧道，或累计被拒 64 次，即被关闭。
- **令牌更换。** 更换隧道的公网服务器或内网服务器时生成新令牌，原来的服务器不再持有可用的令牌。
- **何时下发。** 两台服务器都回报了能力标志（`managed: true`），且公网服务器已回报指纹之前，控制器不会把这条隧道发给任何一端，公网端规则也不会生成（旧版 Agent 会拒绝带 `reverse_tunnel` 字段的规则）。面板显示原因：“Agent 版本过旧”或“等待公网服务器的密钥”。

## 端口与地址

- **公网端口**给用户连接；**隧道端口**给内网服务器连出。两者不能相同。公网端口的监听 IP 为隧道的 `listen_ip`，留空时取公网服务器转发设置中的监听 IP（未设置时监听全部地址），与共同规则相同；隧道端口的监听 IP 总是取转发设置中的监听 IP。
- **端口冲突**（409）：公网端口和隧道端口不能被公网服务器上的规则（含端口段和受管协议网关端口，启用与否都算）、跨面板共享的端口范围或其他隧道占用；隧道端口可以与同一台公网服务器上的其他隧道共用，但不能是其他隧道的公网端口。反过来，普通规则、共同规则和跨面板共享也不能占用隧道持有的端口（即使隧道尚未运行）：发布配置返回 409，共同规则在对应线路上报告冲突。
- **内网服务器连接的地址**是公网服务器转发设置中的转发主机加隧道端口；隧道端口落在转发端口范围内且设置了 NAT 公网起始端口时，按映射换算。公网服务器没有转发设置时无法连出，隧道显示为异常并说明原因。
- **用户入口地址**是转发主机加公网端口（同样按 NAT 映射换算）；没有转发设置时取具体的监听 IP，否则为空。
- 请在公网服务器的云防火墙 / 安全组中放行公网端口和隧道端口：隧道端口只需 TCP；协议含 UDP 时，公网端口还需放行 UDP。内网服务器只需要能连出，不需要任何端口映射。

## 状态

`GET /reverse-tunnels` 为每条隧道给出 `state`：

| 状态 | 含义 |
| --- | --- |
| `disabled` | 已停用 |
| `waiting` | 尚未下发或尚未连通，`reason` 说明原因：公网 / 内网服务器尚未连接面板或 Agent 版本过旧、等待公网服务器的密钥、服务器离线、等待公网服务器应用配置、等待内网服务器连入 |
| `connected` | 公网服务器回报这条隧道已附加在一条隧道连接上；`connected_since_ms` 为建立时间（控制器时钟），`connected_for_secs` 为已建立多久 |
| `error` | 两端回报的错误（例如连接失败、指纹不符、令牌被拒），或一端服务器已删除、公网服务器没有转发地址 |

`upload_bytes` / `download_bytes` 是公网端规则当前计量周期的流量（与流量账本一致）；更换公网端口或公网服务器会开始新的周期。

## 访问与限速

公网端规则中由隧道决定的字段（名称、监听端口、协议、目标、启停、`reverse_tunnel`）只能在反向隧道中修改；在规则发布中修改这些字段返回 400 并说明原因。以下字段可以在面板的“访问与限速”或 `PUT /nodes/{id}/config` 中修改，修改隧道时保留：`allow_sources`、`deny_sources`、`rate_bytes_per_sec`、`max_connections`、`udp_max_sessions`、`quota_bytes`、`expires_at_ms`、`idle_timeout_secs`、`connect_timeout_ms`、`budget_ids`。发布时漏掉公网端规则不会删除它，控制器会按当前设置补回。公网端规则在两端就绪之前不存在，因此只能在隧道运行后设置这些限制。

## 数据与权限

- 记录保存在 `metadata` 的 `reverse_tunnel:<id>`，schema 和恢复日志格式不变：`{id, tenant_id, name, public_node_id, private_node_id, public_port, listen_ip?, protocol: tcp|udp|tcp_udp, target, tunnel_port, enabled, owner_id, created_at_ms, updated_at_ms}`。`owner_id` 是公网端规则及其流量所属的账户：操作者属于该租户时为操作者，否则为租户的第一个管理员。
- 令牌在 `reverse_tunnel_token:<id>`；每台服务器回报的能力与指纹在 `reverse_tunnel_node:<服务器 id>`（只在变化时写入）。Agent 在自己的状态中保存密钥（`agent_reverse_tunnel_key`）和最近一次收到的隧道（`agent_reverse_tunnels`），重启后在连上控制器之前就恢复运行。
- 两台服务器必须属于同一租户且不同；暂停或到期的服务器不能运行隧道（409）。
- 读取需要登录会话或带 `read` 的 API 令牌；新建、修改、删除需要可写角色，API 令牌还需 `nodes:write`，并检查对两台服务器的写权限。其他租户看不到这些记录，访问返回 404；只读用户返回 403。
- 审计动作为 `reverse_tunnel.create`、`reverse_tunnel.update`、`reverse_tunnel.delete`，详情不含令牌。公网端规则的发布另记 `config.publish`。
- 删除服务器不受隧道记录阻止：它所在隧道的公网端规则随之移除，隧道显示该服务器“已删除”，可以删除隧道记录。

## 同步协议

- 控制器在每次同步中发送 `SyncResponse.reverse_tunnels` `{key, listeners:[{listen, tunnels:[{id, token}]}], dials:[{id, server, fingerprint, token, target, protocol}]}`。`key` 表示这台服务器是某条隧道的公网端、应生成密钥；`listeners` 是作为公网端的隧道监听及其接受的隧道；`dials` 是作为内网端要保持的隧道。没有隧道时各项为空。旧版 Agent 忽略这个字段；对新版 Agent，旧控制器没有这个字段表示没有隧道。
- Agent 只向发送了这个字段的控制器返回 `EngineStats.reverse_tunnel` `{managed, fingerprint?, tunnels:[{id, role: public|private, connected_secs?, error?}]}`，因为旧控制器拒绝未知的统计字段。控制器忽略其中的未知字段。`managed: true` 是能力标志；`fingerprint` 在 Agent 生成密钥后出现。最多回报 1024 条隧道，单条错误最长 512 字节，超出时整个同步返回 400。
- `GET /agent/watch` 在某台服务器的隧道变化后返回一次 `reverse_tunnels_changed: true`，新版 Agent 立即同步，旧版忽略。

## 兼容性

- **旧 Agent + 新控制器**：旧 Agent 不回报 `managed`，隧道停在“Agent 版本过旧”，控制器不发送公网端规则，也不让它出现在发给任一端的配置中；其他功能不受影响。升级后自动下发。
- **新 Agent + 旧控制器**：旧控制器不发送 `reverse_tunnels`，新 Agent 不回报 `reverse_tunnel` 统计，也不运行任何隧道。
- **降级**：控制器无法区分“旧 Agent”和“新 Agent 重启后的第一次同步”（两者都不带能力标志），所以一台服务器回报过能力之后，控制器不会因为某次同步没有带它就收回隧道，否则每次 Agent 重启都会撤下又重建公网端规则。旧 Agent 的规则格式拒绝未知字段，会拒绝带 `reverse_tunnel` 的整份配置并继续运行上一修订。因此把公网服务器降级到不支持反向隧道的版本之前，请先删除它作为公网端的隧道。

## API

| 方法 | 路径 | 请求 / 结果 |
| --- | --- | --- |
| GET | `/api/v1/reverse-tunnels` | 可见的隧道：记录字段（不含 `owner_id`）加 `{public_node_name, private_node_name, public_missing, private_missing, state, reason, connected_since_ms, connected_for_secs, entry, rule_id, upload_bytes, download_bytes}` |
| POST | `/api/v1/reverse-tunnels` | `{name, public_node_id, private_node_id, public_port, listen_ip?, protocol, target, tunnel_port?, enabled?}` → 隧道视图；`tunnel_port` 缺省 29123，`enabled` 缺省 true |
| PUT | `/api/v1/reverse-tunnels/{id}` | 同上；`enabled` 省略时保持不变 |
| DELETE | `/api/v1/reverse-tunnels/{id}` | `{ok:true}` |

错误：输入无效 400（名称 1–120 字节、两端为同一台服务器、跨租户、端口为 0 或两端口相同、目标不是 `host:端口`、监听 IP 为组播地址、未知字段或无法解析的请求体），权限 403，不存在或不可见 404，冲突 409（端口被占用、服务器已暂停或到期）。

## 面板

「转发规则」的“全部转发”页面下方、“端点组与转发链”之后是“反向隧道（NAT 穿透）”区块：

- 列表显示名称和隧道端口、公网服务器与公网端口、内网服务器与目标、协议、状态及原因（已连接时显示已建立多久）、用户入口地址和“复制”、流量，以及“编辑”“访问与限速”“停用 / 启用”“删除”。一端服务器已删除时只能删除。
- “＋ 新建反向隧道”选择公网服务器和内网服务器（只列出与公网服务器同一租户的其他服务器），填写公网端口（“自动选择”取公网服务器转发端口范围中最低的空闲端口：跳过规则、端口段、网关端口、其他隧道的公网端口和隧道端口，以及表单中的隧道端口）、目标和协议；“高级选项”中是隧道端口和公网端口的监听 IP。表单附有简短说明：公网端口给用户，隧道端口给内网服务器连出；目标中的 `127.0.0.1` 指内网服务器自己；请在公网服务器的云防火墙中放行两个端口。
- 公网端规则在“按服务器”的规则列表中标为“反向隧道公网端”，操作为“在反向隧道中管理”；“全部转发”的路径列表不单独列出它。

## 验证与限制

- 单元测试：`reverse_mux::managed` 中密钥保存后指纹不变，两条隧道共用一条连接、只允许 TCP 的隧道拒绝 UDP、错误令牌和错误指纹被拒、公网端移除隧道后不能再打开；`reverse_tunnel` 中公网端规则的渲染（保留编号、计量周期和可编辑字段，更换端口开始新周期）和输入校验。
- `crates/relay-platform/tests/reverse_tunnels.rs` 6 项集成测试：
  - `tunnels_are_checked_against_servers_tenants_and_ports_in_both_directions`：同一台服务器、跨租户、两端口相同；与规则和共同规则双向的端口冲突（公网端口与隧道端口）；两条隧道共用隧道端口；隧道之间的公网端口与隧道端口冲突；编辑保留自身端口；暂停的服务器 409。
  - `nothing_is_sent_until_both_agents_can_and_the_public_key_is_reported`：旧 Agent 时什么都不发、原因依次为两端“版本过旧”和“等待公网服务器的密钥”，格式错误的指纹不算；指纹到达后公网端得到监听（监听 IP 与共用的隧道端口）和公网端规则，内网端得到经 NAT 映射的连接地址、钉住的指纹、令牌、目标和协议，第三台服务器只得到自己的隧道；令牌不出现在视图、审计和配置中；规则编辑只能改限制，改目标 400，漏掉公网端会补回；编辑隧道保留规则编号、计量周期和限制；停用与删除后两端都不再收到。
  - `changing_servers_renews_the_token_and_the_watch_wakes_both_ends`：更换内网服务器生成新令牌，新旧两端的配置等待各被唤醒一次。
  - `deleting_a_server_is_not_blocked_and_shows_it_missing`。
  - `the_api_checks_input_roles_scopes_and_tenants`：400 / 409、只读用户与只有 `read` 的令牌 403、`nodes:write` 令牌可写、其他租户 404 且不能使用本租户的服务器、响应中没有令牌。
  - `the_private_end_holds_its_targets_to_its_outbound_set`：两个真实 Agent，目标写作 `localhost:端口`；内网服务器绑定拒绝该名称的出站规则集后，TCP 和 UDP 都到不了目标（目标没有收到连接或数据报），公网端为两个来源各写一条拦截记录；改为只拒绝 `::1` 后经 `127.0.0.1` 照常连通，再拒绝两个地址又被拒绝，都无需发布。
  - `a_private_server_bound_to_an_outbound_set_needs_an_agent_that_holds_its_tunnels_to_it`：旧 Agent 时新建、启用和改目标返回 409，停用的隧道可以新建；升级后通过；降级后已有隧道照常下发、改名可以、改目标 409，`uncovered` 为 `reverse_tunnels`。
  - `real_agents_carry_metered_tcp_and_udp_through_the_tunnel`：控制器、公网与内网两个真实 Agent 和回显目标在本机回环上运行；TCP 与 UDP 经隧道往返，流量账本与流量页面的字节数精确相等，拒绝来源生效，错误指纹和错误令牌被拒，隧道连接被切断后内网端重连，停用后公网端口和隧道端口关闭且内网端不再连出。
- `scripts/test_web_reverse_tunnels.cjs` 在中英文下运行面板代码，核对列表、新建（含租户过滤与“自动选择”）、编辑、停用、删除和“访问与限速”发送的请求。
- `sudo python3 scripts/check_linux_reverse_tunnel.py --binary target/release/relay --workdir /tmp/rt-check`（仅 root，一次性网络命名空间）：内网服务器和局域网主机位于丢弃一切主动入站包的 nftables 家庭路由器之后，客户端位于另一个命名空间。检查路由器确实拒绝入站；两条隧道（局域网主机 `192.168.10.20:7000` 的 TCP+UDP，内网服务器自身 `127.0.0.1:7001` 的 TCP）共用一条出站隧道连接；客户端的 128 KiB TCP 与 20 个 UDP 数据报经公网服务器到达回显服务；路由器 WAN 链路上抓不到明文令牌；公网端计量；公网服务器的 Agent 重启后内网端重新连上；停用关闭公网端口、删除最后一条隧道关闭隧道端口和出站连接；清理。在本仓库的验证环境中：创建后 5.1 秒两条隧道连通；客户端到局域网主机的 128 KiB TCP 校验一致、20 个 UDP 数据报全部返回；公网端计量上下行各 151202 字节，恰为 131072 字节 TCP 加 20130 字节 UDP 载荷；公网 Agent 重启后 5.1 秒恢复；抓到的 326287 字节 WAN 流量中没有令牌和目标地址。
- 不支持：内网服务器经 HTTP 代理连出、一条隧道多个目标、端口段、在公网端叠加 WS / TLS / PROXY 等传输选项。隧道断开期间公网端口仍在监听，新连接会被接受后关闭，而不是被拒绝。
- 未覆盖：真实家庭路由器、运营商级 NAT、IPv6 网络和云安全组；这些需要在真实环境中确认。
