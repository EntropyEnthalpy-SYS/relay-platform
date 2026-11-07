# 出口代理：经上游 SOCKS5 代理连接目的地

代理服务规则（客户端自己指定目的地的规则）默认由运行它的服务器直接连接目的地。设置**出口代理**后，这台服务器改为经一个上游代理连接目的地：

```text
客户端 → 入口代理服务 → （转发路径）→ 运行代理服务的服务器 → 上游 SOCKS5 代理 → 真实目的地
```

上游地址不是目的地：目的地仍由客户端的请求决定，上游只负责代为连接。它对应 Zero Forwarder 文档中的“出口代理”。本版本只支持 **SOCKS5** 上游；Hysteria2、TUIC、Juicity 上游和“引用另一条规则作为上游”暂不支持（见文末）。

## 适用的规则

只有入口为以下代理服务的规则可以设置出口代理：

- SOCKS5（`inbound_socks5`）
- HTTP CONNECT（`inbound_http_connect`）
- HTTP/2 CONNECT（`inbound_http2_connect`）
- Shadowsocks（`inbound_shadowsocks`）

这四种入口建立目的地连接时都走同一条拨号路径：没有出口代理时直接连接，有出口代理时经上游连接。普通端口转发、协议网关和反向隧道公网端的目标由配置决定，不能设置出口代理（400：`an egress proxy applies only to rules whose clients choose the destination: a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks inbound`）。

## 字段

规则上的 `egress_proxy`（未设置时省略，未知字段被拒绝）：

```json
{
  "egress_proxy": {
    "kind": "socks5",
    "servers": ["proxy-a.example.com:1080", "203.0.113.20:1080", "[2001:db8::20]:1080"],
    "username": "relay",
    "password": "upstream-secret"
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `kind` | 上游类型，目前只有 `socks5` |
| `servers` | 1 到 8 个上游地址：`域名:端口`、`IPv4:端口` 或 `[IPv6]:端口`，按顺序尝试；不区分大小写地重复会被拒绝 |
| `username`、`password` | 上游的 RFC 1929 用户名和密码，各 1..255 字节，不含控制字符；必须同时设置或同时省略。全部上游地址共用这一组凭据。它们与入口的客户端凭据（如 SOCKS5 入口的 `username` / `password`）无关 |

校验失败返回 400，错误信息只提到出错的地址或字段名，从不包含密码。

规则还须满足：

- 传输协议为 `tcp`（400：`an egress proxy carries TCP only; set the rule's protocol to TCP (UDP is never sent around the egress proxy)`）；
- Shadowsocks 入口关闭 UDP over TCP（400：`an egress proxy carries TCP only; turn off Shadowsocks UDP over TCP`）。

## 行为

### 目的地 ACL 先于上游

规则的目的地允许 / 拒绝列表和端口列表（见 [DESTINATION_ACL.md](DESTINATION_ACL.md)）以及入口的“允许内网目的地”设置，仍按客户端请求的**真实目的地**检查，检查在连接上游之前进行。被拒绝的目的地不会产生任何到上游的连接，计入和以前相同的拒绝统计与拦截记录。

### 域名与 DNS

- 客户端请求的是 IP 地址时，按原有规则检查后，把这个 IP 发给上游（SOCKS5 ATYP IPv4 / IPv6）。
- 客户端请求的是域名时：
  - 入口**允许内网目的地**，且目的地 ACL 只凭域名和端口就能判定允许（没有 IP / CIDR 条目可能拒绝它的地址，允许列表为空或有匹配的域名条目）时，域名**原样**交给上游（SOCKS5 ATYP 域名），由上游解析。本服务器不做 DNS 查询。
  - 其他情况，包括入口**不允许内网目的地**（四种入口的默认设置），本服务器先用规则的解析器解析域名，按 ACL 和公网地址检查逐个过滤，只把通过检查的 IP 发给上游，依次尝试。

  这样做是为了保持原有的检查语义：只有在本服务器解析，才能确认域名不指向内网地址或 ACL 拒绝的地址。如果把域名交给上游解析，一个指向 `127.0.0.1` 或云厂商元数据地址的域名就可能经由部署在本机或同一内网的上游绕过检查。

  **DNS 泄露**：在第二种情况下，本服务器（及其配置的 DNS 服务器）会看到客户端访问的域名，上游只看到 IP。需要由上游解析域名时，请在入口中允许内网目的地，并且不要在目的地 ACL 中使用 IP / CIDR 条目；此时内网地址的防护交给上游自己。

### 多个上游与故障转移

- 按 `servers` 的顺序尝试。连接失败（解析失败、连接被拒绝或超时、握手中途断开）时换下一个地址。
- 最近 10 秒内失败过的地址排在其他地址之后；某个地址成功后立即恢复正常顺序。这个状态只在 Agent 内存中，按规则保存。
- 规则的 `connect_timeout_ms` 覆盖整个过程（连接上游、认证、上游连接目的地）。每个剩余的上游地址分得剩余时间的相同份额，所以一个不响应的地址不会占满全部时间。
- 以下情况**不再**换下一个上游，因为全部上游共用同一组凭据，换了也会得到相同结果：用户名或密码被拒绝、上游要求认证而规则没有设置凭据、对方不是 SOCKS5 服务器、上游对目的地回复错误（如 `host unreachable`）。上游对某个目的地 IP 回复错误时，如果本服务器解析出多个地址，用新的上游连接尝试下一个地址。

### 出站绑定、多路径与环路保护

- 规则的 `outbound_bind`（出口绑定的源地址 / 网卡）用于到上游的连接，与直接连接目的地时相同；MPTCP 出站设置也作用于这条连接。
- 到上游的连接按原有方式登记路由保留和环路检测（与直接连接目的地相同）。

### 计量、配额与限速

计量、配额、共享预算、流量账本和各级限速与没有出口代理时**完全相同**：按客户端与入口之间转发的字节计算，SOCKS5 握手的几十个字节不计入。

### 失败的统计和日志

连不上上游、认证失败、上游的 SOCKS5 错误回复都算作**目的地连接失败**，与直接连接目的地失败一样计入 `failed_connections`（HTTP CONNECT / HTTP/2 CONNECT 客户端收到 502，SOCKS5 客户端收到失败回复）。拦截记录仍只记录被目的地 ACL 拒绝的连接。Agent 调试日志中的原因（默认看不到，见下方说明）形如：

- `egress proxy proxy-a.example.com:1080 is unreachable: …`
- `egress proxy proxy-a.example.com:1080 did not answer in time`
- `egress proxy proxy-a.example.com:1080 rejected the username and password`
- `egress proxy proxy-a.example.com:1080 could not connect to example.org:443: host unreachable (SOCKS5 reply 4)`

这些信息只包含上游地址和目的地，**从不包含用户名和密码**。

**默认日志级别不显示这些原因。** 它们由 `relay_platform::engine` 模块以调试（DEBUG）级别记录（日志消息为 `TCP session ended`）；Agent 未设置 `RUST_LOG` 时使用 `relay=info,relay_platform=info`，只输出 INFO 及以上。排查时可临时给 Agent 进程设置 `RUST_LOG=relay=info,relay_platform=info,relay_platform::engine=debug` 并重启 Agent；该模块的其他调试信息也会一并输出，日志量会增加。排查结束后去掉这项设置并再次重启，恢复原来的级别。这只是临时排障手段，不要作为生产服务的长期设置。

### 当前连接

在“连接…”对话框（[CONNECTIONS.md](CONNECTIONS.md)）中，经出口代理的会话 `remote` 是实际连接的上游地址（解析后的 IP 和端口），`destination` 仍是客户端请求的目的地；`via` 不变（只用于下一跳是另一台 Relay 服务器的情况）。面板在“下一跳”一列显示“出口代理”和上游地址。

## UDP、UDP over TCP 与 BIND

出口代理只转发 TCP。本版本没有实现上游 SOCKS5 UDP ASSOCIATE，而且用户期望全部出站流量都经过上游，所以 Relay 不会把 UDP 绕过上游直接发给目的地：

- 发布时拒绝 UDP：规则的传输协议必须是 TCP，Shadowsocks 入口必须关闭 UDP over TCP（400，见上文）。因此 SOCKS5 UDP ASSOCIATE、Shadowsocks UDP 和 UDP over TCP 都不可用。
- 运行时 SOCKS5 入口对 UDP ASSOCIATE 和 BIND 请求回复 `command not supported`（回复码 7）：BIND 需要对端直接连回本服务器，会绕过上游。

面板在开启出口代理时自动把传输协议改为 TCP，并关闭 Shadowsocks 的 UDP over TCP。

## 兼容性与旧 Agent

与 0.147.0 分方向限速、0.148.0 测速和连接统计的做法相同：

- 控制器在每个同步回复中带 `egress_proxy: true`（为 false 时省略）。新 Agent 收到后在统计中回报 `stats.egress_proxy: {}`；控制器第一次收到时写入元数据 `egress_proxy_node:<节点 id>`，此后这台服务器视为支持，删除服务器时一并删除。`GET /nodes` 的 `egress_proxy_support` 显示该状态。
- Agent 的规则拒绝未知字段，所以早于本版本的 Agent 会拒绝带 `egress_proxy` 的配置。没有支持记录的服务器上，任何发布路径（单节点发布、批量预览和发布、回滚、模板、共同规则、链路）给它带 `egress_proxy` 的规则时返回 **409**：
  - `the agent on server <名称> is too old for egress proxies; upgrade it first`
  - 从未连接过面板的服务器：`server <名称> has not connected to the panel yet; egress proxies need its agent to report in first`

  检查与限速相同，在所有发布路径共用的一处进行，出口代理不会在某台服务器上被静默丢弃。
- 跨面板共享的规则由共享定义重新生成，共享协议中没有出口代理字段；发布时给共享的规则设置出口代理返回 400（`rule <名称> belongs to share <名称>; a share's rules cannot have an egress proxy`）。反向隧道公网端不能使用代理入口，因此也不能设置出口代理（400）。
- 不使用出口代理的配置与以前完全相同，旧 Agent 照常运行。
- 新 Agent 对 0.148.0 控制器：旧控制器不发 `egress_proxy`，新 Agent 不回报（旧控制器的 `EngineStats` 拒绝未知字段），转发不受影响。
- 面板把这些原因翻译为界面语言显示；规则编辑器在所选服务器尚未回报支持时，在出口代理一节中提示先升级 Agent。
- 升级顺序与以往相同：先升级控制器，再升级 Agent。已回报支持的 Agent 如果被降级，控制器仍会下发该字段，旧 Agent 拒绝配置并回报应用错误。

## 凭据

上游密码与 Shadowsocks 密码、SOCKS5 / HTTP CONNECT 入口凭据的处理方式相同：

- 作为规则内容保存在节点配置和配置历史中，随配置下发给 Agent；能读取这台服务器配置的用户（`GET /nodes/{id}/config`）可以看到它，用于编辑。模板和共同规则保存规则内容时同样包含它。
- 审计记录只记录修订号和规则数量（`config.publish` 等），不包含规则内容。
- 错误信息、Agent 日志、控制器日志和 Agent 的统计回报中不出现密码；`egress_proxy` 回报是空对象，调试输出只显示是否设置了认证。
- 面板中密码使用密码输入框；规则表只显示第一个上游地址和地址数量；入口的分享链接不包含出口代理。

## 界面

规则编辑器在启用 SOCKS5、HTTP CONNECT、HTTP/2 CONNECT 或 Shadowsocks 代理服务时显示“出口代理（经上游代理连接目的地）”一节：

- **出口代理**：关闭，或 SOCKS5。
- **上游代理地址**：每行一个，最多 8 个，按顺序尝试。
- **上游用户名**、**上游密码**：留空表示不认证。
- **导入链接**：粘贴 `socks5://user:pass@host:port`（也接受 `socks5h://`）后点“导入链接”，地址追加到列表（已存在则不重复），用户名和密码按百分号编码解码后填入。`hysteria2://`、`tuic://` 等链接提示暂不支持。

输入错误显示在该节下方的错误行，不会保存。规则表的“目标”列为设置了出口代理的规则显示“出口代理 · 地址”标记。

## 限制与暂不支持

- 只支持 SOCKS5 上游（无认证或用户名 / 密码认证）。**Hysteria2、TUIC、Juicity 上游暂不支持**，导入这些链接会提示不支持。
- **引用另一条规则（另一个端口）作为上游暂不支持**。需要时可以把另一条 SOCKS5 代理服务规则的监听地址直接填为上游地址。
- 不支持 UDP（见上文），不支持 SOCKS5 BIND。
- 每条规则最多 8 个上游地址，全部共用同一类型和凭据；不按延迟选择，只按顺序故障转移。
- 不允许内网目的地时，域名由本服务器解析（见“域名与 DNS”）。
- 上游连接不复用：每个客户端连接（HTTP/2 CONNECT 的每个隧道）各自连接上游。

## 测试

- `crates/relay-platform/src/egress.rs` 单元测试：字段校验、SOCKS5 握手和 RFC 1929 认证、域名请求、各类拒绝，以 Relay 自己的 SOCKS5 服务作为上游。`destination_acl.rs` 测试只凭域名的 ACL 判定。
- `crates/relay-platform/tests/egress_proxy.rs`：真实控制器和 Agent 在回环地址上运行。
  - 四种入口都只经要求认证的上游到达目标：上游记录了连接和凭据，目标看到的来源是上游的出站地址而不是本服务器，`outbound_bind` 生效，会话的 `remote` 是上游，流量计数与负载相同。
  - 第一个上游不可用时换到第二个。
  - 错误的密码给出明确的错误，日志、审计、诊断报告和统计中都不含密码。
  - 目的地 ACL 在连接上游之前拒绝。
  - UDP 和 BIND 被拒绝，UDP 规则发布时为 400。
  - 旧 Agent 的 409（单节点、批量、模板、共同规则），回报后发布成功。
- `scripts/test_web_egress_proxy.cjs`：编辑器各字段、链接导入、校验错误、请求内容、规则表标记和 409 原因的翻译，中英文各运行一次。
