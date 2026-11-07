# 连接统计与拦截记录

对应 Zero Forwarder 文档“连接诊断与测速”中端口的 **连接统计**（实时连接、累计统计、转发器分布）和 **拦截记录**：

- **当前连接**：一条规则此刻打开的 TCP 连接和 UDP 会话，看得到客户端、目标或代理请求的真实目的地、下一跳和实时字节数。面板打开时才向服务器要，不保存。
- **累计统计**：这条规则自 Agent 启动以来已接受的连接、各目标的拨号结果（即“转发器 / 下一跳分布”）和按原因统计的拒绝次数。
- **拦截记录**：被拒绝的连接、UDP 会话和数据报，带时间、来源、原因和简短详情。同一规则、来源 IP 和原因在 60 秒内合并为一条并计数。

## 在哪里看

- **转发规则 → 按服务器** 的规则操作，以及 **全部转发** 每条转发（入口规则）的操作中有 **连接…**：打开对话框，依次是当前连接（带文字筛选和“刷新”）、累计统计和这条规则的拦截记录。
- **转发规则 → 按服务器** 的服务器工具栏有 **拦截记录**：这台服务器所有可见规则的拦截记录，可按规则筛选。
- 页面搜索 “连接”“拦截”“connections”“blocked” 会找到这两个页面；使用手册“读懂监控与告警”中有“连接与拦截记录”一节。

## 当前连接

Agent 在内存中为每个打开的会话登记一项，会话结束时（任何退出路径，包括出错、超时、规则停用）由守卫对象自动移除：

- **TCP**：所有入站类型都在接受连接时登记，包括普通 TCP、TLS、WebSocket（含 TLS）、PROXY 协议、HTTP CONNECT、HTTP/2 CONNECT、SOCKS5（CONNECT、BIND 和 UDP ASSOCIATE 的控制连接）、Shadowsocks（含 UDP over TCP）、自有多路径聚合入口和协议网关的本机桥接。MPTCP 连接对用户态是一条普通 TCP 连接，按 TCP 显示。多路径聚合入口每个聚合会话显示一条，后续加入的子连接不单独列出。
- **UDP**：普通 UDP 规则每个客户端地址一个会话；Shadowsocks UDP 每个关联一个会话。SOCKS5 UDP ASSOCIATE 显示在它的 TCP 控制连接上（协议 `socks5_udp`），数据报字节计入这一条。

每个会话的字段：

| 字段 | 含义 |
| --- | --- |
| `id` | Agent 内的序号 |
| `protocol` | `tcp`、`tls`、`websocket`、`wss`、`socks5`、`socks5_udp`、`http_connect`、`http2_connect`、`shadowsocks`、`shadowsocks_uot`、`multipath`、`gateway`、`udp`、`shadowsocks_udp` |
| `udp` | UDP 会话为 true |
| `client` | 规则看到的客户端地址；带 PROXY 头时是头里的地址 |
| `started_ms` | 开始时间（Unix 毫秒） |
| `target_index`、`target` | 选中的配置目标（序号和配置的地址） |
| `remote` | 连上后实际连接的地址（解析后的 IP 和端口） |
| `via` | 目标是另一台服务器的规则时，下一跳 `{node_id, rule_id}` |
| `destination` | 代理入口（SOCKS5、HTTP CONNECT、HTTP/2 CONNECT、Shadowsocks、协议网关）客户端请求的真实目的地；HTTP/2 CONNECT 一条连接上有多个隧道时显示最近一个 |
| `upload_bytes`、`download_bytes` | 实时上传 / 下载字节数，与流量计量在同一位置累加（客户端 → 目标为上传） |

快照最多列出 **200 个会话，最新的在前**；`totals` 统计全部会话，列表被截断时 `truncated: true`，面板显示“显示最新的 N 个，共 M 个”。

### 请求与刷新

1. 面板请求 `GET /nodes/{id}/rules/{rule}/connections`。控制器内存中没有 2 秒内的快照时，记下这个请求，并通过配置监视（与测速、反向隧道相同的 `GET /agent/watch` 机制，字段 `connections_requested: true`）唤醒 Agent，回答 `state: pending`。
2. Agent 立即同步，同步回复里的 `live_connection_requests` 列出要回报的规则；Agent 随即再同步一次，带上这些规则的快照（每次最多 4 条规则）。
3. 控制器把快照放在内存中；之后 2 秒内的请求直接返回它（`ready`），所以一个用户反复点击也不会让 Agent 更频繁地拍快照。60 秒没人看的快照被丢弃。
4. 面板在 `pending` 时每秒、`ready` 后每 3 秒刷新一次，直到对话框关闭；`no_answer`、`unsupported`、`offline` 或出错时停止，点“刷新”再继续。
5. 请求 30 秒内没有回答时报告一次 `no_answer`，下一次查看重新请求。一台服务器同时最多有 8 条规则在等待快照，超过时返回 429。

## 累计统计

来自 Agent 已经回报的数据，不新增存储：

- `counters.inbound`：已接受的 TCP 连接（没有被连接数上限和来源检查拒绝的）及其入站建立：尝试次数即已接受的连接数，成功为完成入站建立（PROXY 头、TLS、WebSocket 握手）的连接，另有按原因的失败次数和建立耗时合计。还没有连接时没有这一项；UDP 不计入。
- `counters.targets`：每个配置目标的拨号次数、成功次数、失败原因（超时、被拒绝、DNS、对端断开、其他）和建立耗时合计，以及该目标的下一跳 `via`。面板按成功次数算出各目标的占比，即“转发器 / 下一跳分布”。
- `counters.refused`：按原因统计的拒绝次数，来自最近一次快照（Agent 启动以来）；还没有快照时为空。每个 Agent 最多为 4096 条规则分别计数，之后新出现的规则只记拦截记录、不再计数。

这些计数从 Agent 启动开始累计，Agent 重启后归零；与“全部转发”中按小时保存的连接记录（见 [DIAGNOSTICS.md](DIAGNOSTICS.md)）不是同一份数据。

## 拦截记录

在每个拒绝连接、UDP 会话或数据报的地方记录原因。实际存在的原因：

| `reason` | 何时 | `detail` 示例 |
| --- | --- | --- |
| `source_not_allowed` | 规则有来源允许列表，来源不在其中；协议网关的本机桥接只接受回环地址 | `not in the allow list` |
| `source_denied` | 来源在拒绝列表中 | `matches deny-list network 192.0.2.0/24` |
| `proxy_untrusted` | 规则接收 PROXY 头，发送方不在受信任列表 | `PROXY header sender is not trusted` |
| `expired` | 规则已过有效期 | `the rule expired` |
| `connection_limit` | 达到规则的 TCP 连接数上限 | `limit 100 connections` |
| `udp_session_limit` | 达到规则的 UDP 会话上限（普通 UDP 和 Shadowsocks UDP） | `limit 64 UDP sessions` |
| `http2_stream_limit` | 达到 HTTP/2 CONNECT 的并发隧道上限 | `limit 128 streams` |
| `quota` | 规则配额已用完（新会话被拒，或会话进行中用完后被断开） | `quota of 1073741824 bytes used up` |
| `budget` | 共享额度拒绝或未及时授予 | `shared budget refused or not granted in time` |
| `inactive` | 计量器不放行且不属于以上原因：规则未在这台服务器生效 | `the meter admits nothing: the rule is not active here` |
| `no_target` | 没有目标接受新会话：全部暂停、不可用或已满 | `all targets paused` |
| `destination_denied` | 代理客户端请求的目的地不在目的地规则内，或不是公网地址 | 拒绝说明，例如 `10.0.0.1:22 is not a public address` |
| `auth_failed` | SOCKS5、HTTP CONNECT 或 Shadowsocks 认证失败 | 协议模块的错误说明 |
| `handshake_failed` | 代理握手的其他失败（格式错误、不支持的命令、超时等） | 协议模块的错误说明 |

每条记录：`rule_id`、`protocol`、`source`（来源 IP，不含端口）、`reason`、`detail`、`first_ms`、`last_ms`、`count`。`detail` 最多 120 个字符、不含控制字符，只用固定说明、配置中的数值和网段、目的地址或协议模块的错误说明，**从不包含密码、密钥、令牌或数据内容**。

### 合并与上限

- 同一（规则、来源 IP、原因）在第一次之后 60 秒内的重复拒绝合并为同一条，`count` 加一、`last_ms` 更新；60 秒后再出现时开始新的一条。
- 每个 Agent 最多保留 **1000 条**，满了先丢弃最久没有变化的一条；用于合并的索引只指向保留中的记录，也不超过 1000 项。洪水攻击时每次拒绝只是一次短暂加锁和一次哈希查找，详情字符串只在新建记录时生成，内存不会超过这个上限。
- 每条记录有流内不变的 `id` 和每次变化都会更新的 `seq`。控制器在每个同步回复里带上它已收到的位置（`block_cursor: {stream, seq}`，与实时日志的游标做法相同），Agent 只发送这之后变化的记录，每次最多 200 条，其余下次同步再发。记录变化后会再发一次，控制器用新内容替换旧的同一条，**不会重复计数**。Agent 重启后 `stream` 变化，控制器会收到它当时保留的全部记录。
- 控制器为每台服务器在内存中保留最近 **1000 条**，**控制器重启后清空**（与实时日志相同），不写入数据库，也不进入诊断报告。

## 权限与隐私

- 能读取这台服务器配置的用户都可以查看（与读取配置的租户规则相同）：系统管理员看全部；其他用户只能看到自己租户可见的规则，看不到的规则和服务器返回 404，服务器的拦截记录只列出可见规则的记录。只读角色也可以查看。API 令牌需要 `read` 权限。
- **客户端地址和来源 IP 属于个人数据。** 当前连接只在面板打开对话框时向服务器获取，不保存；拦截记录只在内存中保留有限的条数。导出或分享截图前请打码。
- 快照频率有上限：每条规则 2 秒内最多拍一次，每台服务器最多 8 条规则同时等待。

## 同步协议与兼容性

与 0.145.0 反向隧道、0.147.0 分方向限速和测速的做法相同：

- 控制器的每个同步回复带 `live_connections: true`（为 false 时省略）。只有收到它的 Agent 才在统计中回报 `stats.live_connections: {snapshots?: [...], blocks?: {stream, entries}}`；控制器第一次收到时记录 `connections_node:<节点>`，`GET /nodes` 显示为 `connections_support`。控制器在保存统计前取出这个字段，它不会进入保存的统计数据。
- 只有回报过支持的 Agent 才会收到 `live_connection_requests`（为空时省略）和 `block_cursor`，以及配置监视的 `connections_requested`。
- 回报有大小限制：最多 4 个快照，每个最多 200 个会话、地址最长 300 字节；每次最多 200 条拦截记录，详情最多 120 个字符。超过时同步为 400，与其他回报相同。
- **旧 Agent（0.147.0 和测速版本）** 忽略未知的同步字段、从不回报支持，也收不到请求和游标；转发不受影响。面板对它们显示“Agent 版本过旧，请先升级 Agent”，累计统计仍然显示。
- **新 Agent 对 0.147.0 控制器**：旧控制器不发 `live_connections`，新 Agent 不回报（旧控制器的 `EngineStats` 拒绝未知字段），转发不受影响；旧面板没有这些入口。
- 升级顺序与以往相同：先升级控制器，再升级 Agent。

## 开销

- 登记和移除会话各是一次分片（16 个分片之一）上的短暂加锁，期间不等待任何 I/O；字节计数是原子加法，与流量计量在同一处。转发开销的测量见下方“测试”。
- 快照只在面板请求时生成，需要遍历这台服务器的全部会话一次。

## 不包括什么

- **探测采集**（保存扫描 / 探测连接的样本字节）：涉及他人数据内容，不做。
- **从面板关闭连接**：不提供。
- **防火墙规则集**：以后的功能。本功能只记录规则自身的来源 / 目的地 ACL、上限、配额等造成的拒绝。
- 已关闭会话的历史：只显示当前连接；历史成功率见“全部转发”的连接记录。
- 协议网关的公网入口由 sing-box 处理：它自己的来源 ACL 拒绝、认证和握手失败看不到，网关会话的客户端地址显示为本机桥接的回环地址，真实目的地照常显示。
- HTTP/2 CONNECT 的 407 认证质询不记录：HTTP/2 客户端通常先不带凭据发起请求，这是正常的质询流程，记录下来只会产生大量误报。
- 普通转发规则的目标被目的地 ACL 拒绝时计为该目标的拨号失败，不是拦截记录。
- 其他原因的数据报丢弃（如缓冲已满）只计入 `dropped_datagrams`，不是拦截记录。

## 测试

- 单元测试 `connections::tests`：会话在每种退出路径（正常结束、出错返回、panic、任务取消）都会移除；快照最新在前、最多 200 个并统计全部；60 秒窗口内合并、窗口后新建；洪水下记录环和合并索引都有上限；控制器在重发、更新和 Agent 重启时每条只保留一次；回报大小上限；规则协议名称。`store::connections::tests`：请求只发给回报过支持的 Agent、只保留有请求的快照；未回答的请求报告一次 `no_answer` 后重新请求。
- 集成测试 `crates/relay-platform/tests/connections.rs`：通过公开 API 和回环上的真实 Agent，两条 TCP 连接和一个 UDP 会话显示客户端、目标和增长的字节数，关闭后消失；拒绝列表、允许列表和连接数上限产生带正确原因、详情和合并计数的记录，多次同步不重复；SOCKS5 规则显示请求的目的地，目的地 ACL 拒绝被记录；旧 Agent 为 `unsupported` 且收不到请求；超大回报 400；租户和权限检查。
- 网页测试 `scripts/test_web_connections.cjs`（中英文）。
