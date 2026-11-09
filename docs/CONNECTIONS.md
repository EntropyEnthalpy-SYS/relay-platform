# 连接统计与拦截记录

对应 Zero Forwarder 文档“连接诊断与测速”中端口的 **连接统计**（实时连接、累计统计、转发器分布）和 **拦截记录**：

- **当前连接**：一条规则此刻打开的 TCP 连接和 UDP 会话，看得到客户端、目标或代理请求的真实目的地、下一跳和实时字节数。面板打开时才向服务器要，不保存。
- **累计统计**：这条规则自 Agent 启动以来已接受的连接、各目标的拨号结果（即“转发器 / 下一跳分布”）和按原因统计的拒绝次数。
- **断开单个会话**：有权修改规则的用户可以在当前连接里断开某一个会话，不必停用整条规则。断开不是封禁。
- **拦截记录**：被拒绝的连接、UDP 会话和数据报，带时间、来源、原因和简短详情。同一规则、来源 IP 和原因在 60 秒内合并为一条并计数。控制器把它们保存在状态目录的独立文件 `blocks.sqlite` 中，重启后仍在，按天数和条数上限清理。

## 在哪里看

- **转发规则 → 按服务器** 的规则操作，以及 **全部转发** 每条转发（入口规则）的操作中有 **连接…**：打开对话框，依次是当前连接（带文字筛选和“刷新”）、累计统计和这条规则的拦截记录。
- **转发规则 → 按服务器** 的服务器工具栏有 **拦截记录**：这台服务器所有可见规则的拦截记录，可按规则筛选，每页 200 条，“加载更早的记录”翻到下一页。
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

## 断开单个会话

有写权限的用户（系统管理员和租户管理员，不含只读角色）在 **连接…** 对话框的当前连接表中看到“断开”。点击后先确认，确认框写明：**这只结束当前会话，不是封禁**——TCP 客户端可以立即重新连接，UDP 客户端的下一个数据报会建立新会话；要阻止来源，请用规则的来源允许 / 拒绝列表或防火墙规则集（[FIREWALL.md](FIREWALL.md)）。确认后面板发出请求，并每秒查看一次结果，最多 35 秒。

不是每个会话都能断开：只有下表中经过真实断开测试的类型显示“断开”，其他显示“—”。协议网关的会话是网关的本机桥接会话，来源是回环地址、不是真实客户端，面板会注明这一点（见下文“何时不能断开”）。

### 哪些会话可以断开

可否断开由 Agent 在登记会话时按规则配置和会话类型（TCP 或 UDP）一次定下（`Session.terminable`），之后不再改变；会话显示的协议名（例如 SOCKS5 UDP ASSOCIATE 之后显示为 `socks5_udp`）变化不影响它。Agent 收到请求时以登记时的值为准，不能断开的回答 `unsupported`；控制器在面板、`GET …/connections` 的 `terminable` 和请求预检中都只认 Agent 回报的值，并且对协议网关规则一律不提供。只有一种入站组合有真实断开测试、证明客户端和目标两侧的业务流都已结束时，才定为可以断开。客户端一侧和目标一侧各自结束：下表的目标一侧（普通、TLS、WebSocket、多路径）各有测试，与各种入站组合搭配；入站一侧只有表中列出的组合可以断开：

| 规则的入站 / 去向 | 可断开 | 断开后的效果 | 真实断开测试（`crates/relay-platform/tests/connections.rs`） |
| --- | --- | --- | --- |
| 普通 TCP（IPv4 和 IPv6） | 是 | 客户端读到 EOF，目标连接关闭，同规则其他连接继续 | `one_session_of_each_inbound_that_can_end_closes_on_both_sides`、`one_session_ends_from_the_panel_while_the_others_go_on` |
| 普通 UDP | 是 | 目标套接字关闭，之后目标的回包不再转发；客户端再发数据报会建立新会话 | 同上两项 |
| HTTP CONNECT | 是 | 客户端 EOF，目标关闭 | `one_session_of_each_inbound_that_can_end_closes_on_both_sides` |
| SOCKS5 CONNECT、BIND | 是 | 客户端 EOF；CONNECT 的目标、BIND 的对端连接关闭 | 同上 |
| SOCKS5 UDP ASSOCIATE | 是 | 控制连接关闭，UDP 中继端口不再转发；中继正在解析目的地域名（DNS 不回答）时也立即结束 | `one_session_ends_from_the_panel_while_the_others_go_on`、`a_socks5_udp_session_ends_while_its_relay_resolves_a_name` |
| HTTP/2 CONNECT | 是，按整条连接 | 会话是整条 HTTP/2 连接：其上全部隧道结束、各自的目标关闭，其他连接的隧道继续；其上仍在拨号（等待域名解析）的流随之结束，得不到隧道。**单条隧道（子流）不单独列出，也不能单独断开** | `one_session_of_each_inbound_that_can_end_closes_on_both_sides`、`an_http2_connect_session_ends_while_one_of_its_streams_dials` |
| TLS、WebSocket、WebSocket + TLS 入站 | 是 | 客户端 EOF，目标关闭；从入口或出口服务器断开都可以 | `tls_websocket_and_multipath_sessions_end_from_either_server` |
| TLS 上的 HTTP/2 CONNECT（ALPN h2）、SOCKS5、HTTP CONNECT | 是 | 同各自不带 TLS 时 | `proxy_header_and_tls_proxy_sessions_end_on_both_sides` |
| 带 PROXY 协议头的 TCP 会话 | 是 | 客户端 EOF，目标关闭；会话来源显示协议头中的地址 | 同上，实测四种：不带 TLS 的 v1 头；TLS 握手之前的 v1 头（`placement: before_tls`）；TLS 内的 v1 头（`inside_tls`）；TCP + UDP 规则的 TCP 会话上不带 TLS 的 v2 头。v2 头与 TLS 的组合没有单独测试 |
| MPTCP（客户端和目标两侧都是 MPTCP） | 是 | 客户端 EOF，目标关闭 | `an_mptcp_session_ends_on_both_sides`（需要内核开启 MPTCP；与仓库其他 MPTCP 测试一样默认不运行，需 `--include-ignored` 显式运行） |
| 以 TLS / WebSocket / 多路径连到下一跳的规则，包括每条路径都走 WebSocket + TLS 的多路径 | 是 | 同上（在入口服务器断开）；多路径的全部路径及其 WebSocket 驱动都在入口会话的任务组里 | `tls_websocket_and_multipath_sessions_end_from_either_server`；路径走 WebSocket 的多路径：`a_multipath_inbound_over_websocket_is_one_session_not_ended_alone` |
| 多路径聚合入口（路径为 TLS） | 是，按聚合会话 | 关闭整个聚合会话及其全部路径，目标关闭；加入时的子连接是短暂的设置会话，不单独断开 | `tls_websocket_and_multipath_sessions_end_from_either_server` |
| 多路径聚合入口，路径为 WebSocket + TLS | 否（`unsupported`） | — 每个聚合会话只列一条，加入的路径交出连接后立即离开列表。每条路径的 WebSocket 连接由各自的驱动持有，加入的路径的驱动不在创建会话的任务组里，回答 `closed` 时无法保证这些连接都已关闭，所以不提供。可以在入口服务器断开（上一行之前那一行） | `a_multipath_inbound_over_websocket_is_one_session_not_ended_alone`：两条路径时出口只列一条，回答 `unsupported` 且立即返回，转发继续 |
| 协议网关（任何协议，含 UDP ASSOCIATE 后显示为 `socks5_udp` 的桥接会话） | 否（`unsupported`） | — | `gateway_bridges_and_shadowsocks_sessions_are_not_ended_alone` |
| Shadowsocks（TCP、UDP over TCP、UDP） | 否：整条规则的会话都回答 `unsupported` | — | `shadowsocks_sessions_answer_unsupported_and_keep_forwarding`：用测试中的 Shadowsocks 2022 客户端实际建立 TCP 会话、UDP over TCP 会话和 UDP 关联并转发数据，请求断开后回答 `unsupported`，之后的数据照常转发到目标 |
| 带出口代理或反向隧道公网端的规则 | 否 | — | 未做断开测试，所以不提供 |
| WebSocket 或多路径入站里的 SOCKS5 / HTTP CONNECT，带 PROXY 协议头的规则的 UDP 会话（v2；同一规则的 TCP 会话可以断开，见上） | 否 | — | 这些组合没有断开测试，所以不提供 |

### 会话身份

- Agent 每次启动生成一个新的运行实例号 `instance`（32 位十六进制）。会话序号 `id` 在同一实例内递增、不复用，但 Agent 重启后又从 1 开始。
- 快照带上实例号，请求同时写明 `instance`、`session_id` 和规则。Agent 只在实例号是自己的、这个序号确实是该规则的会话时才结束它。所以 Agent 重启后，即使新进程里有同一序号的会话，也不会被误断开。

### 结果

| `state` | 含义 |
| --- | --- |
| `pending` | 控制器在每次同步回复中把请求发给 Agent，等待回答 |
| `closed` | Agent 取消了会话，会话的任务已结束、离开了列表，并且它派生的全部任务（SOCKS5 UDP 中继和回包、HTTP/2 每条流的处理和隧道、多路径驱动和各路径、WebSocket 驱动）都已结束，两侧套接字已关闭 |
| `not_found` | 这个实例里没有这条规则的这个会话：它已经结束 |
| `stale_instance` | Agent 已重启，旧实例的会话都已随之结束。控制器在新实例的回报到达时直接给出这个结果，请求不会发给新实例 |
| `unsupported` | 这类会话不能单独断开（见上表） |
| `timed_out` | 已取消，但 3 秒内会话仍未结束；请刷新查看 |
| `expired` | 30 秒内没有 Agent 的回答（例如 Agent 刚断线），控制器不知道会话是否已结束；可以再次请求。之后迟到的回答仍会更新这条请求（例如改为 `closed`） |
| `unknown` | 更新版本 Agent 的、这个控制器不认识的回答 |

只有 `closed` 表示控制器确认会话已结束；其他结果都不会显示为成功。

### 重复与过期

- **重复**按同一服务器、同一规则、同一 `(instance, session_id)` 判断：存在还在等待或已经有回答的请求时，再次请求返回那一条（HTTP 200，`duplicate: true`），不会再发一次，也不再写审计。只有 `expired` 的请求可以重新发起，得到新的请求号。
- 请求号相同的请求再次到达 Agent（例如上一次回报丢失）时，Agent 重复之前的回答（保留最近 64 个），不会把已断开的会话再报成 `not_found`。
- 每台服务器最多 16 个请求同时等待，超过时返回 429。

### 请求放在哪里、控制器重启

- 请求和结果只在控制器内存中，不写数据库元数据。已结束的请求保留 10 分钟供面板查询，每台服务器最多 128 个。
- 控制器重启后内存中的请求全部丢失：`GET …/terminations/{id}` 返回 404；还没发出或已发出但没有回答的请求不再发送，Agent 已经执行的断开不受影响。审计日志中的 `connection.terminate` 记录仍在。重启后请刷新连接列表确认会话是否还在，需要时重新请求。
- 已发出但没有回答的请求：Agent 收到请求后最多等 3 秒确认会话结束（超时回答 `timed_out`），回答随下一次同步送回；控制器在请求发出后 30 秒内收不到回答则判为 `expired`。过期在同步提交之后、或面板查询这条请求时判定并审计，所以被拒绝或回滚的同步不会丢掉过期审计。

### 何时不能断开（409）

- **离线**：服务器 90 秒内没有同步（与连接状态 `offline` 的判断相同）。按最近一次同步的时间判断，而不是数据库中每分钟才写一次的时间，所以同步间隔较长（如 `--poll-seconds 50`）的在线服务器不会被误判为离线。
- **旧 Agent**：Agent 的回报不带实例号（0.150.0 及更早，或降级后），返回 `this server's agent cannot end single sessions; upgrade it first`。
- **Agent 已重启**：请求的实例号不是这台服务器最近一次回报的实例号。Agent 重启后、新的列表到来前，面板上旧实例的会话不显示“断开”（`can_terminate` 和各会话的 `terminable` 为 false），`instance` 仍是旧实例。
- **Agent 回报这个会话不能断开**（Shadowsocks、出口代理、反向隧道等，见上表）。
- **协议网关规则**：无论 Agent 回报什么，控制器都返回 409。客户端外层的 TLS / QUIC 连接由协议引擎持有；受管网关的公网端口由 Agent 前置持有时，这些前置连接目前也不登记到连接列表。连接页只显示本机桥接会话，来源是回环地址，一条外层连接可以对应多条桥接会话。即使关闭桥上的一条，也只结束这一条流，不会断开客户端外层的 TLS / QUIC 连接，客户端可以立即再开新流，所以这类会话不提供单独断开。前置连接以真实来源登记、可以单独断开，计划在后续版本提供。

### 各协议的实际效果

断开就是取消这个会话：会话的任务被取消，它派生的任务登记在会话自己的任务组里，随之取消。任务组里有：SOCKS5 UDP 中继和回包，HTTP/2 每条流的处理（由会话自己的执行器派生）和隧道，多路径驱动和各路径，客户端和目标两侧的 WebSocket 驱动（它们持有套接字；被中止的驱动在其套接字释放之前仍计在组内）。例外是路径走 WebSocket 的多路径入站：每条路径的 WebSocket 驱动在这条连接自己的任务组里，丢弃连接时被中止，但不计入任何会话，所以这类会话不可断开（见上表）。Agent 只在会话的任务已离开列表、并且任务组已空时才回答 `closed`；会话的任务无论怎样结束（正常、出错、panic、被中止），守卫都会取消任务组并让会话留在列表中直到任务组变空，所以也不会提前回答 `closed` 或 `not_found`。组变空之后不会再有新任务加入，这一点依赖下一节逐个核对的接线，不是由类型或测试强制的。每种类型的效果和对应测试见上文“哪些会话可以断开”。

### 任务归属：结构保证与确定性测试

**结构保证**（读代码核对，没有一个测试能单独证明）：

- `TaskTracker::close()` 不阻止之后的登记，`Live::tasks()` 是 `pub(crate)` 也只限制在本 crate 内调用，并不阻止 crate 内的代码裸 `tokio::spawn`。所以“组变空后不再有新任务”依赖以下接线：
  - 会话自己的任务（`tcp_listener` 中 `tasks.spawn` 的那个）在结束之前，经 `tcp_session` 的任务组参数派生：SOCKS5 UDP 中继（`socks5_udp_association`），多路径驱动（`multipath::bridge` → `driver.rs`），客户端一侧的 WebSocket 驱动（`websocket::accept`；路径走 WebSocket 的多路径入站除外，见上），目标一侧的 WebSocket 驱动（`open_tcp_target` / `activate_target` / `try_target` / `open_multipath_path` → `websocket::connect`），HTTP/2 每条流的处理（`InSession` 执行器）。这些都发生在会话任务的 future 里，`finish()` 和守卫的析构都在它结束之后。
  - 已在组内的任务再派生：HTTP/2 隧道（由流处理任务派生），多路径路径 worker（驱动内 `track_future`），SOCKS5 UDP 回包（由中继任务派生）。派生者自己在组内，组在它结束前不会变空。
  - 健康探测的 WebSocket 驱动用引擎的探测任务组，不属于任何会话。
  - 在 `engine.rs`、`http2_connect.rs`、`websocket.rs`、`multipath/`、`socks5.rs` 中逐个核对了 `tokio::spawn`：会话路径上没有裸 spawn。`socks5.rs` 的三处在单元测试中；`http2_connect.rs` 的两处属于不经规则引擎、不登记会话的独立 HTTP/2 CONNECT 监听器（`serve`、`serve_tls`）。
- `Tracked::drop` 的两个分支：守卫只存在于运行时上派生的任务（TCP 会话、UDP 会话）的 future 里。任务正常结束、出错、panic 或被中止时，都在运行时的工作线程上析构，`Handle::try_current()` 成功；任务组不空时派生一个等待者，组空后再移出列表。运行时关闭时还没结束的任务也在运行时上下文中析构（在 tokio 1.54.1 的多线程和单线程运行时上各实测一次），这时派生的等待者不会再运行，会话留在登记表里；但运行时已停，不会再有回答，登记表随引擎释放。“没有运行时”分支在生产路径中不可达，只在测试于运行时之外直接丢弃守卫时触发，这时立即移出列表。

**确定性测试**（接线坏了会失败，交接时附变异结果）：

- `connections::tests::a_session_is_closed_only_after_what_it_spawned_ended_however_its_task_ended`（Registry 层）：守卫直接丢弃、panic、被中止时，派生的任务结束前不回答 `closed`。
- `http2_connect::tests::stream_handlers_and_their_tunnels_are_in_the_sessions_task_group`：仍在拨号的流处理任务计入会话任务组；隧道建立并转发后，任务组在取消前不会变空；取消后连接结束，隧道在放开它的流之前（测试让它停在这一步）任务组仍不变空，放开后目标读到结束，任务组才变空。
- `an_http2_connect_session_ends_while_one_of_its_streams_dials`（引擎层）：连接上一条流正在等一个不回答的 DNS 时断开整条连接，立即回答 `closed`、会话离开列表，已有隧道两侧关闭，拨号的流得不到隧道。
- `websocket_transport::transport_flush_waits_for_wire_backpressure`：WebSocket 驱动在传入的任务组里，流打开时任务组不会变空；丢弃流后任务组变空，这时套接字已经关闭。
- `a_multipath_inbound_over_websocket_is_one_session_not_ended_alone`：路径走 WebSocket 的多路径入站只列一条、不可断开，加入的路径不会一直留在列表里。

**不算证据的**：`terminate` 里的 `live.work.is_empty()` 检查与守卫的延迟移出重复，去掉它没有测试失败，它不是测试保护的保证，只是多一道检查。SOCKS5 UDP 的域名解析改为可取消之后，引擎层没有不加产品钩子、又能长期保留的屏障；`tcp_listener` 里 `session.finish().await` 这个调用点由 Registry 层的结构保证兜底（删掉它，守卫仍等任务组变空才移出列表），它本身留着是为了让引擎关闭时等待派生的任务。

### 权限与审计

- 需要能看到这条规则（他租户为 404）且有写权限：只读角色 403；API 令牌需要 `nodes:write`。`GET …/connections` 的 `can_terminate` 和每个会话的 `terminable` 也按同样的条件给出：用没有 `nodes:write` 的令牌查看时为 false。请求体必须带 `"confirm": true`，否则 400。
- 每次新请求写审计 `connection.terminate`（操作者、服务器、规则、实例号、会话序号、协议和客户端地址）；Agent 的回答或控制器判定的 `stale_instance` 写 `connection.terminate.result`（操作者为 `node:<节点>`）；`expired` 也写 `connection.terminate.result`（操作者为 `controller`），之后迟到的回答再写一条。

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
- 控制器只保留一份：同一 Agent 运行（`stream`）中同一 `id` 的记录只有一行，`seq` 相同或更旧的重发不改变任何内容，变大的替换原行，所以计数不会重复相加。Agent 重启后旧运行的记录保留，与新运行的记录并列。

### 保存与留存

- 控制器把记录写入状态目录中的 `blocks.sqlite`（权限 0600，SQLite 的 `-wal`、`-shm` 文件同为 0600，自带 `user_version`，比当前版本新的文件会被拒绝打开），与 `history.sqlite` 一样**独立于 `controller.sqlite`，不在 `relay backup` 备份和恢复日志中**，`relay restore` 也不恢复它。丢失这个文件只丢拦截记录，不影响配置、计量和审计。需要另外保存时，在控制器停止后复制它（连同 `blocks.sqlite-wal`）并保持 0600；它含来源 IP。
- 每台服务器的游标（`{stream, seq}`）与记录在同一个事务里写入，控制器重启后继续从这里接收，Agent 不会把已收到的记录再算一次。
- **留存**：每条记录在最后一次变化后保留 `--block-record-days` 天（默认 30，1–365），每台服务器最多 `--block-records-per-node` 条（默认 10000，100–100000），超出时先删最久没有变化的。按天清理在控制器启动打开文件时执行一次，之后在记录到达时最多每分钟一次。所以记录和其中的来源 IP 都不会无限积累。安装器的 `controller.json` 可写 `block_record_days`、`block_records_per_node`，见 [LINUX_DEPLOYMENT.md](LINUX_DEPLOYMENT.md)。
- 删除服务器时，它在 `blocks.sqlite` 中的记录和游标一并删除。
- **文件不能用时控制器照常运行**：`blocks.sqlite` 是符号链接、权限不是 0600（例如复制回来时成了 0644）、文件损坏、来自更新的版本，或目录只读、磁盘已满时，控制器在启动时把原因写进日志一次，然后不带拦截记录运行，直到修好文件后重启。期间 `GET /nodes/{id}/blocks` 返回 `unavailable: true` 和空列表，面板写明拦截记录暂时不可用；当前连接和断开会话不受影响；控制器告诉 Agent 从它已发送的位置继续，Agent 不会每次同步都重发同样的记录（这段时间的记录不保存）。运行中写入失败只在开始失败和恢复时各记一次日志。
- **分页**：`GET /nodes/{id}/blocks` 按最后一次变化从新到旧，每页最多 1000 条（默认 200，面板每页 200），按规则或整台服务器查询都走索引，有更早的页时返回 `next_before`，作为下一页的 `before`。翻页期间又变化的记录会移到最前，不会在后面的页里再出现一次。
- 不进入诊断报告。

## 权限与隐私

- 能读取这台服务器配置的用户都可以查看（与读取配置的租户规则相同）：系统管理员看全部；其他用户只能看到自己租户的规则，看不到的规则和服务器返回 404，服务器的拦截记录只列出自己租户规则的记录（按记录到达时规则所属的租户；规则不明的记录只有系统管理员看得到）。只读角色也可以查看。API 令牌需要 `read` 权限。断开会话的权限见上文。
- **客户端地址和来源 IP 属于个人数据。** 当前连接只在面板打开对话框时向服务器获取，不保存；拦截记录按上面的留存上限保存在控制器的 `blocks.sqlite` 中，不记录数据内容和凭据。导出或分享截图前请打码。
- 快照频率有上限：每条规则 2 秒内最多拍一次，每台服务器最多 8 条规则同时等待。

## 同步协议与兼容性

与 0.145.0 反向隧道、0.147.0 分方向限速和测速的做法相同：

- 控制器的每个同步回复带 `live_connections: true`（为 false 时省略）。只有收到它的 Agent 才在统计中回报 `stats.live_connections: {snapshots?: [...], blocks?: {stream, entries}}`；控制器第一次收到时记录 `connections_node:<节点>`，`GET /nodes` 显示为 `connections_support`。控制器在保存统计前取出这个字段，它不会进入保存的统计数据。
- 只有回报过支持的 Agent 才会收到 `live_connection_requests`（为空时省略）和 `block_cursor`，以及配置监视的 `connections_requested`。
- 回报有大小限制：最多 4 个快照，每个最多 200 个会话、地址最长 300 字节；每次最多 200 条拦截记录，详情最多 120 个字符。超过时同步为 400，与其他回报相同。
- **旧 Agent（0.147.0 和测速版本）** 忽略未知的同步字段、从不回报支持，也收不到请求和游标；转发不受影响。面板对它们显示“Agent 版本过旧，请先升级 Agent”，累计统计仍然显示。
- **新 Agent 对 0.147.0 控制器**：旧控制器不发 `live_connections`，新 Agent 不回报（旧控制器的 `EngineStats` 拒绝未知字段），转发不受影响；旧面板没有这些入口。
- **断开会话**：控制器的每个同步回复还带 `connection_termination: true`。Agent 只有收到它之后才在 `live_connections` 中加上 `instance` 和 `terminations`（最多 16 个回答），因为 0.150.0 控制器的这个结构拒绝未知字段。控制器在回报带实例号时记录 `connection_termination_node:<节点>`，回报不带实例号时删除（降级）；只有这样的 Agent 才收到 `connection_terminations`（最多 16 个），且只收到发给它当前实例的请求。唤醒仍用 `connections_requested`。
- 每个会话的 `terminable` 也只在收到 `connection_termination` 之后发送（为 false 时省略），因为 0.150.0 控制器的会话结构同样拒绝未知字段。
- **0.150.0 Agent 对本版控制器**：忽略新字段，不带实例号，断开请求返回 409 要求升级；当前连接和拦截记录照常。**本版 Agent 对 0.150.0 控制器**：收不到 `connection_termination`，不发送新字段。
- **运行中把控制器换回旧版本**：Agent 上一次同步时按新控制器的回复开启的回报，会在下一次请求中被旧控制器以 HTTP 422（未知字段）拒绝。本版 Agent 收到 422 且开着这类回报时，下一次请求不带任何按控制器要求才发的回报（断开会话、连接、出口代理、限速、测速、防火墙、DNS、WireGuard、MPTCP、反向隧道；随被拒请求发出的断开回答这次没有送达，同一个控制器运行仍在等待的请求会在之后的回复中重发，Agent 对已回答过的请求重复原来的回答，见下文），按正常间隔重试，转发不中断；旧控制器的回复会重新开启它支持的回报。同一个控制器运行（`controller_instance` 不变）声明支持、却第二次以 422 拒绝时，这些回报保持关闭、Agent 不再执行断开请求，直到另一个控制器运行回复，期间只记一次 error，不会每隔一次同步被拒一次。第一次被拒之后，直到一次带回报的同步被接受（或另一个控制器运行回复）之前，Agent 也不执行断开请求：回答要随下一次请求送回，而下一次可能再被拒绝，会话断开了却得不到回答。控制器在每次同步回复中重发仍在等待的请求，所以这期间到达的请求推迟到一次带回报的同步被接受时执行并回报，通常只晚一次同步；从面板发起请求起 30 秒内没有这样的同步（例如第二次被拒后回报保持关闭），才判为 `expired`，这时会话保持原样，可以之后重新请求。被接受的带回报的同步会清除这一计数。没有可关闭的回报时仍按原来的做法停止，以保护身份和账本一致性。用真实的 0.150.0 控制器验证过：同一个 Agent 进程在新控制器、0.150.0 控制器、新控制器之间切换，已有连接每 200 毫秒收发一次、全程没有失败，见“测试”。
- 降级控制器到 0.150.0：旧版不读取 `blocks.sqlite`，拦截记录回到只在内存中的做法，文件原样留在状态目录；再次升级后继续使用。
- 升级顺序与以往相同：先升级控制器，再升级 Agent。

## 开销

- 登记和移除会话各是一次分片（16 个分片之一）上的短暂加锁，期间不等待任何 I/O；字节计数是原子加法，与流量计量在同一处。转发开销的测量见下方“测试”。
- 快照只在面板请求时生成，需要遍历这台服务器的全部会话一次。

## 不包括什么

- **探测采集**（保存扫描 / 探测连接的样本字节）：涉及他人数据内容，不做。
- **封禁**：断开单个会话不阻止来源再连，阻止请用来源列表或防火墙规则集。
- 协议网关会话、Shadowsocks、出口代理和反向隧道会话的单独断开，路径走 WebSocket 的多路径入站、WebSocket 或多路径入站里的代理入站和带 PROXY 协议头的规则的 UDP 会话的单独断开，以及 HTTP/2 CONNECT 单条隧道的单独断开（见上文）。
- **防火墙规则集**：以后的功能。本功能只记录规则自身的来源 / 目的地 ACL、上限、配额等造成的拒绝。
- 已关闭会话的历史：只显示当前连接；历史成功率见“全部转发”的连接记录。
- 协议网关的公网入口由 sing-box 处理：它自己的来源 ACL 拒绝、认证和握手失败看不到，网关会话的客户端地址显示为本机桥接的回环地址，真实目的地照常显示。
- HTTP/2 CONNECT 的 407 认证质询不记录：HTTP/2 客户端通常先不带凭据发起请求，这是正常的质询流程，记录下来只会产生大量误报。
- 普通转发规则的目标被目的地 ACL 拒绝时计为该目标的拨号失败，不是拦截记录。
- 其他原因的数据报丢弃（如缓冲已满）只计入 `dropped_datagrams`，不是拦截记录。

## 测试

- 单元测试 `connections::tests`：会话在每种退出路径（正常结束、出错返回、panic、任务取消）都会移除；会话的任务不经 `finish` 就结束（直接丢弃守卫、panic、被中止）时，守卫取消会话派生的任务，会话留在列表中、请求回答 `timed_out`，放行派生任务后正在等待的请求回答 `closed`（`a_session_is_closed_only_after_what_it_spawned_ended_however_its_task_ended`，用永不自行结束的子任务做屏障，不依赖时间）；`terminable` 逐条覆盖每个判断分支，按 TCP 和 UDP 会话分别判断：带 PROXY v2 的 TCP + UDP 规则的 TCP 会话可以断开、UDP 会话不可以，路径走 WebSocket 的多路径入站不可以，单独的 WebSocket 或多路径入站可以（`only_rules_whose_sessions_were_tested_to_end_alone_say_so`）；快照最新在前、最多 200 个并统计全部；60 秒窗口内合并、窗口后新建；洪水下记录环和合并索引都有上限；回报大小上限；规则协议名称；断开只对本实例、本规则的会话生效（旧实例的同一序号为 `stale_instance`、他规则为 `not_found`、登记为不可断开的为 `unsupported`），会话改了显示的协议名（网关桥接改为 `socks5_udp`）后仍不可断开，`terminable` 只在控制器要求时回报；会话派生的任务结束前不回答 `closed`；同一请求重复到达得到同一回答，3 秒未结束为 `timed_out`。
- `http2_connect::tests::stream_handlers_and_their_tunnels_are_in_the_sessions_task_group`、`websocket_transport` 的 `transport_flush_waits_for_wire_backpressure`：HTTP/2 流处理任务、隧道和 WebSocket 驱动都在会话的任务组里（见上文“任务归属”）。
- `store::connections::records::tests`：重发、增长和两端重启时每条只保留一次，控制器重启后记录和游标仍在；分页不重不漏，按规则翻页（`before` 与 `rule_id` 同用）；两种查询都走索引，较早版本建立、缺少按规则索引的 `user_version` 1 文件打开时补上索引（`a_version_1_file_from_before_the_rule_index_gets_it`）；租户只读到自己规则的记录；每台服务器的条数上限、按天清理（打开文件时，写入时最多每分钟一次）、文件及 `-wal`、`-shm` 权限 0600、拒绝更新版本的文件和越界的留存设置。
- `store::connections::tests`：请求只发给回报过支持的 Agent、只保留有请求的快照；未回答的请求报告一次 `no_answer` 后重新请求；断开请求需要确认和写权限，他租户 404；重复请求返回同一条；只发给当前实例，回答后不再发送且只审计一次；Agent 重启时为 `stale_instance`；30 秒未回答为 `expired`（由 `controller` 审计；读到回报后被拒绝的同步不判过期，下一次提交的同步才判并审计）后可重新请求，迟到的回答仍更新并审计；Agent 重启后、新列表到来前，旧实例的会话不可断开；每台最多 16 个；降级后 409；控制器重启后为 404；面板和预检只认 Agent 回报的 `terminable`，协议网关规则即使 Agent 回报可断开也不提供、请求 409；没有 `nodes:write` 的令牌看不到可断开；数据库中的时间已过 90 秒但最近一次同步较新时仍在线，真正超过 90 秒时 409 离线；`blocks.sqlite` 为 0644、损坏、符号链接或目录只读时控制器照常同步、告诉 Agent 继续的位置、`/blocks` 为 `unavailable`；规则不明的记录只有系统管理员看得到；删除服务器时清除其记录、游标和两项支持标记。
- 集成测试 `crates/relay-platform/tests/connections.rs`：通过公开 API 和回环上的真实 Agent，两条 TCP 连接和一个 UDP 会话显示客户端、目标和增长的字节数，关闭后消失；拒绝列表、允许列表和连接数上限产生带正确原因、详情和合并计数的记录，多次同步不重复；SOCKS5 规则显示请求的目的地，目的地 ACL 拒绝被记录；断开两条 TCP 连接中的一条，客户端被关闭、另一条继续收发、客户端可立即重连，重复请求返回同一回答，别的实例号 409，不存在的会话 `not_found`；断开 UDP 会话后下一个数据报建立新会话；断开 SOCKS5 UDP ASSOCIATE 后控制连接关闭、中继端口不再转发；只读用户、只读令牌 403，他租户 404；按原始响应字节检查，每个会话只有一个 `terminable` 键；控制器在同一地址重启后、Agent 还连不上它时拦截记录已在（证明是从文件读出，而不是 Agent 重发），Agent 继续发送时计数不重复，分页与留存设置经 API 返回，他租户 404，文件权限 0600；旧 Agent 为 `unsupported` 且收不到请求，断开 409；超大回报 400；租户和权限检查；控制器运行中换成只认 0.150.0 字段的版本时，Agent 只被拒绝一次、之后不带新字段继续同步，已有连接继续收发，换回后重新回报实例号；声明支持却一直拒绝的控制器只拒绝两次，之后回报保持关闭、转发继续，控制器重启（另一个运行）后再试两次；这个控制器在每次回复里都要求断开一条已有连接，Agent 在两次拒绝之间和之后都不执行，这条连接一直正常收发。在 Agent 的转发引擎上逐类断开（上文表中的测试）：断开后客户端读到 EOF、目标一侧连接关闭（UDP 为目标的迟到回包不再转发），同规则其他会话继续；HTTP/2 CONNECT 断开整条连接时其上两条隧道都结束、另一条连接的隧道继续，回答 `closed` 时活动隧道数已降为 1；带 PROXY 头的 TCP 会话实测不带 TLS 的 v1、TLS 握手之前的 v1、TLS 内的 v1 和 TCP + UDP 规则上的 v2 四种；路径走 WebSocket 的多路径入站在出口只列一条、回答 `unsupported`、转发继续，在入口断开时两侧结束；协议网关桥接（真实走一次带认证的 SOCKS5 UDP ASSOCIATE）回答 `unsupported` 且继续转发；Shadowsocks 的已建立 TCP 会话、UDP over TCP 会话和 UDP 关联回答 `unsupported` 且继续转发。SOCKS5 UDP 中继卡在不回答的 DNS 上时、HTTP/2 CONNECT 连接上有流卡在不回答的 DNS 上时，断开都立即回答 `closed`。
- 网页测试 `scripts/test_web_connections.cjs`（中英文）：只对可断开的会话显示“断开”，确认框写明不是封禁，取消确认不发请求，确认后重新打开连接对话框并跟进回答；只读用户没有这一列，旧 Agent 提示升级；协议网关的会话注明来源是网关本机桥接、不是真实客户端；拦截记录读取失败或 `unavailable` 时会话列表和“断开”照常显示；服务器拦截记录翻页、留存说明和不可用说明。
- 真实进程（不在仓库内，交接时另附脚本）：同一个本版 Agent 进程在本版控制器、真实的 0.150.0 控制器二进制、本版控制器之间切换（同一状态目录和端口），一条已有连接每 200 毫秒收发一次，全程没有失败，每个控制器上新连接都可用，0.150.0 拒绝一次可选回报后 Agent 只记一次警告、不停止，换回后同一 Agent 运行的会话重新可断开。
- 未覆盖：IPv6 只测了普通 TCP；PROXY v2 头与 TLS 的组合（TLS 前、TLS 内）没有单独的断开测试，只测了 v1；MPTCP 测试默认不运行（需内核支持，显式运行）；完整 `scripts/verify.sh`。
- 部署测试 `scripts/tests/test_deployment.py` 的 `ControllerBlockRecordSettings`：留存设置成为控制器参数，不写时包装脚本不变，越界或类型错误被拒绝。
