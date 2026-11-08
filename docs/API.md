# 开发版 API 契约

基础路径 `/api/v1`，JSON。用户与节点分别使用独立的 256-bit 随机 Bearer 凭据；持久化存储只保存服务端令牌哈希。用户会话八小时过期。Agent 的长期凭据保存在自己的私有状态库。所有跨机器请求须通过 HTTPS。

API 尚处开发阶段；以 `model.rs`、`lease.rs` 等公开模型的严格字段定义为准。未识别字段返回错误，不能假装启用尚未实现的功能。单次请求限制 2 MiB。

| 方法 | 路径 | 请求或用途 |
| --- | --- | --- |
| POST | `/auth/login` | `{username,password}` → `{token,user,expires_in_seconds}` |
| GET | `/session` | 当前用户与角色 |
| POST | `/auth/logout` | 撤销当前会话 |
| GET / POST | `/nodes` | 按可选 q/kind/group/tag/lifecycle 筛选可见节点；`{name,tenant_id?,lease_policy?,settings?}` 创建节点并返回一次性注册令牌；省略或 `null` 的 `lease_policy` 为离线（可用优先）模式，`{}` 或 `{ttl_ms}` 为严格租约 |
| DELETE | `/nodes/{id}` | 删除已撤销或未注册、没有有效执行租约、且未被其他节点 `via`、DNS 记录、订阅、模板或预算引用的节点；一并删除其规则、配置历史与用量记录，保留审计和已用凭据栅栏；仍被引用时返回 409 |
| PUT | `/nodes/{id}/profile` | `{expected_revision,name,settings}`；更新完整资料，独立于转发修订 |
| POST | `/nodes/profiles` | `{updates:[{node_id,update}]}`；原子保存 1..100 个节点资料，逐节点返回修订 |
| GET | `/nodes/{id}/config` | 当前期望配置，包含修订号和规则 |
| PUT | `/nodes/{id}/config` | `{expected_revision,rules,rate_bytes_per_sec?,rate_limits?}`；并发冲突返回 409，成功生成下一版本。省略 `rate_bytes_per_sec` 保留节点总限速，`null` 取消；`rate_limits`（上传 / 下载 / 突发限速）同样省略保留、`null` 取消，见[分别限制上传 / 下载与突发限速](#upload-download-and-burst-speed-limits) |
| GET | `/nodes/{id}/credential` | 可见节点的身份阶段/版本、轮换/撤销/替换回执与受保护配额周期；不返回秘密或哈希 |
| POST | `/nodes/{id}/credential/rotate` | `{expected_revision}` 请求 Agent 自行生成并轮换凭据；权限与版本检查 |
| POST | `/nodes/{id}/credential/revoke` | `{operation_id,expected_revision,reason}`；退役身份、保留旧窗口与未知预留 |
| POST | `/nodes/{id}/credential/replace` | `{operation_id,expected_revision,enrollment_token,valid_for_seconds,offline_stop_attested?,lease_policy?}`；签发或重签限时替换令牌 |
| GET | `/nodes/{id}/health` | 实际修订对应的目标健康、年龄、候选原因、探测流量与容量；按节点权限过滤 |
| GET | `/nodes/{id}/history` | 最近 100 次配置修订 |
| POST | `/nodes/{id}/rollback` | `{revision,expected_revision}`；把历史规则作为新修订发布，账本不回滚 |
| GET | `/nodes/{id}/rules/{rule}/share?host=&port=&name=` | 受管协议规则的分享链接与二维码 `{uri,qr_svg}`；权限同读取配置；AnyTLS 与非协议规则 409，见 PROTOCOL_GATEWAYS.md |
| POST | `/nodes/{id}/drain` | `{draining}`；把所有 `via` 指向该节点的上游目标设为（或取消）维护排空，在一个批次中发布有变化的上游节点；没有上游指向它时返回 409，已是目标状态时返回空结果 |
| GET | `/topology` | 当前可见节点、配置、声明边、根规则及应用状态 |
| POST | `/configurations/allocate-endpoints` | `{hops:[{node_id,listen?,advertise?}]}`；只读分配建议端点，返回 `endpoints,configs`；需写权限及 `nodes:write` token scope |
| POST | `/configurations/preview` | `{updates:[{node_id,expected_revision,rules,rate_bytes_per_sec?,rate_limits?}]}`；只读校验并返回候选配置及完整差异，需要写权限；两个限速字段与单节点发布相同 |
| POST | `/configurations/publish` | 同预览请求；1..64 个节点的期望配置在同一事务中提交 |
| GET / POST | `/users` | 列出用户；`{username,password,role,tenant_id?}` 创建用户 |
| POST | `/users/{id}/revoke-sessions` | 撤销该用户全部现有 Web 会话 |
| GET / PUT | `/users/{id}/rate` | 跨节点用户总限速。PUT `{rate_bytes_per_sec, upload_bytes_per_sec?, download_bytes_per_sec?}`（每项 1024..=2^40）仅系统管理员：`rate_bytes_per_sec` 省略或 `null` 取消合计限速（与以前相同），上传 / 下载省略保留、`null` 取消；新增上传或下载限速而承载该用户启用规则的服务器有 Agent 不支持时 409。GET 按租户可见，返回 `{user_id, rate_bytes_per_sec, nodes, upload_bytes_per_sec, upload_nodes, download_bytes_per_sec, download_nodes}`：各方向的总速率和各节点当前份额、实测速率、是否用满、距上次同步毫秒数。`GET /users` 的每个用户同样带 `upload_bytes_per_sec`、`download_bytes_per_sec` |
| POST | `/tenants` | `{name}`；仅系统管理员 |
| GET | `/usage` | 最近 2,000 条已上报的规则/周期累计记录，不是全库聚合接口 |
| GET / POST | `/budgets` | 返回 `{allocation_paused,budgets}`；创建 `{scope,scope_id,name,limit_bytes,quantum_bytes}` |
| GET | `/budgets/{id}/reservations` | 按所属租户只读分页查看开放预留；可选 `after` 游标，每页最多 100 条 |
| PUT | `/budgets/{id}` | `{expected_revision,limit_bytes,quantum_bytes}`；修改额度，不清零用量 |
| GET | `/audit` | 最近 200 条全局审计；仅系统管理员 |
| GET | `/recovery` | `{enabled,healthy,head}`；仅系统管理员，读取控制器恢复日志状态 |
| GET | `/control/metrics` | 仅系统管理员；返回本次控制器运行的节点同步统计 |
| GET | `/metrics` | 认证的 Prometheus 文本：构建信息、恢复日志、预算额度、规则累计用量、HTTP 请求分类与延迟直方图、反向 mux 进程可用性/控制/流/字节、节点在线、应用/期望修订、配置同步、最后同步、活动 TCP/UDP、接纳/拒绝/失败/丢弃/预热计数、转发字节、应用错误、系统资源、计量/额度恢复、目标健康，以及多路径会话/路径/负载/失败计数。独立部署的 mux 指标由 `reverse-mux-server --metrics-listen` 提供；控制器中的 `relay_reverse_mux_process_available 0` 表示遥测不在该进程 |
| GET | `/telemetry` | 可见节点最近 24 小时的逐次回报采样和事件，供总览页使用；见下文“0.19.0 遥测” |
| GET | `/history?range=1h\|24h\|7d` | 可见节点的 7 天历史：回报汇总与逐段真实 TCP 连接结果；见下文“0.131.0 连接记录与 7 天历史” |
| GET | `/logs?source=&after=` | 仅系统管理员；控制器和各节点最近的日志行，`source` 为节点 ID 或 `controller`，省略为全部；见下文“0.132.0 实时日志与诊断报告” |
| GET | `/diagnostics/report` | 仅系统管理员；当前问题列表与节点、规则（不含凭据）、最近 1 小时逐段连接、事件和日志的快照 |
| GET | `/alerts` | 系统管理员读取全部；租户管理员读取本租户通道、事件和发送记录；返回 `can_manage` |
| PUT | `/alerts/settings` | `{maintenance_until_ms}`；仅系统管理员，登录会话 |
| POST | `/alerts/channels` | `{name,enabled,min_severity,target,tenant_id?}`；仅系统管理员，登录会话 |
| PUT / DELETE | `/alerts/channels/{id}` | 修改或删除通道；修改时留空的地址、令牌和密钥保留原值 |
| POST | `/alerts/channels/{id}/test` | 立即发送一条测试消息，失败返回 502 和原因 |
| GET | `/capabilities` | 实现能力与待实现能力目录，不代表完整发布验收 |
| POST | `/agent/enroll` | `{node_id,enrollment_token,credential,identity_revision_supported?}`；返回 `{enrolled:true,credential_revision}`；替换注册必须声明能力为 true |
| POST | `/agent/credential/rotate` | `{request_id,expected_revision,credential,lease}`；事务换钥并返回可重试回执 |
| POST | `/agent/reconcile` | 节点凭据认证；分页获取权威用量下限和相同修订的配置 |
| POST | `/agent/budgets/recover` | 严格节点在开启监听前验证原状态预留、补报消费和处理待确认请求 |
| POST | `/agent/sync` | 节点凭据认证，上报用量/状态并获取期望配置 |
| GET | `/agent/watch?after=N` | 节点凭据认证的长轮询：期望修订号大于 N 时立即返回 `{desired_revision}`，否则最多等待 25 秒返回当前值 |

注册时 Agent 先在本地生成并持久化独立 `credential`，然后请求控制器绑定。一次性令牌只允许首次绑定；相同已绑定凭据可以重试确认，原注册令牌不能绑定第二个凭据。控制器不需要保存可还原的节点秘密。0.16.0 支持管理员发起、Agent 自行执行和中断恢复的常规凭据轮换；完整合同见 [NODE_CREDENTIALS.md](NODE_CREDENTIALS.md)。0.17.0 增加撤销和全新状态替换，包含操作幂等、限时令牌、旧租约窗口和配额周期保护，见 [NODE_IDENTITY.md](NODE_IDENTITY.md)。

同步请求：

```json
{
  "ledger_id": "reconciliation-returned-ledger-id",
  "need_config": false,
  "applied_revision": 1,
  "apply_error": null,
  "usage": [{
    "rule_id": "rule-one",
    "meter_epoch": "period-one",
    "sequence": 3,
    "upload_bytes": 1024,
    "download_bytes": 512
  }],
  "stats": {
    "active_tcp": 0,
    "active_udp": 0,
    "accepted_tcp": 1,
    "rejected_connections": 0,
    "failed_connections": 0,
    "dropped_datagrams": 0,
    "forwarded_upload_bytes": 1024,
    "forwarded_download_bytes": 512
  }
}
```

响应包含 `controller_instance`、可选 `config` 和 `credential_rotation`、`acknowledgements`、`server_time_ms`。`controller_instance` 每次 API 服务启动变化，在线 Agent 据此重新对账并补报曾确认的数据。每批最多 1,024 条累计用量；只有规则/周期属于该节点才可入账。同序号与同累计值可以重放；序号或字节倒退、同序号改值返回 409。确认到旧序号不会清除后来新增长的未确认字节。

规则、流量与配置修订的数据库整数上限为有符号 64 位范围。API 使用 JSON 整数，精确处理超过 `2^53-1` 的数值时，客户端须使用无损整数解析；浏览器配额输入仅接受 JavaScript 安全整数，界面显示经过单位换算的近似值。

恢复请求格式为 `{ledger_id:null,after:null,expected_revision:null}`；首次由控制器分配或返回该节点既有账本 ID。返回 `{node_id,ledger_id,revision,usage,next,config}`。后续请求携带同一 `ledger_id`、上一页 `next` 对象及 `expected_revision`。每页最多 256 条历史计量周期，按 `(rule_id,meter_epoch)` 排序，最后一页 `next:null` 且包含同一修订的 `config`。分页期间配置变化返回 412，Agent 重头对账；单次恢复最多 4096 页，超过则拒绝激活并要求处理归档。

本地较旧的累计值在未开始转发时提高到控制器确认值；本地较新且向量单调的值保留并重新补报。对账只降低“确认序号”，不降低已接纳计量。相同序号不同值、较新序号出现任一方向倒退、账本身份不一致都会失败，不以简单取最大值掩盖分叉。在正常离线重启已经转发的情况下，若远端反而领先，Agent 停止转发并要求恢复，避免与在途数据混合。

恢复标记只在完成全部账本分页并成功应用配置后清除。历史上已删规则的用量只作为禁用计量行恢复；不能因此开启历史规则。真实身份或历史分叉导致的 409 不会自动修改；不能删库绕过。

TLS 配置使用 `Rule.inbound_tls={identity,client_ca}` 与 `Target.tls={server_name,ca,identity}`，未设置则为普通流量。所有 ID 引用节点本地材料，API 不接收 PEM 私钥；入口/出口 TLS 不接受 UDP 或双协议，也不接受一条规则中明文与加密出口混用。节点材料错误通过 `apply_error` 报告，期望修订和实际修订会保持不同。

额度的 `scope` 为 `user`、`tenant` 或 `node`，每个对象只允许一个额度。`quantum_bytes` 范围为 1..67108864，单位字节。创建需要相关节点确认停用规则；更新需要修订号一致，且新总额不能低于 `committed_bytes`。`consumed_bytes` 是已上报累计接纳量；`committed_bytes-consumed_bytes` 是包含未上报消费的剩余预留，不等于可重新发放的余额。读取按租户隔离，创建和修改需要写权限，均有审计记录。

规则上的 `budget_ids` 由控制器按当前 owner/tenant/node 自动重算；用户提交和历史回滚无法删除适用的预算。0.4.0 Agent 同步可带 `budget:{run_id,requests,reports,settle_only}`。`requests` 每项为 `{budget_id,request_id,minimum_bytes}`；`reports` 每项为 `{grant_id,consumed_bytes,surrender}`。响应的 `budget` 包含 `grants`、`acknowledgements`、`allocation_paused`、`cancelled_requests`；每项 grant 为 `{grant_id,budget_id,request_id,run_id,bytes}`，确认项与 report 同形，取消项为请求 ID。三个响应集合各最多 1024 项；请求和报告也各最多 1024 项。最小请求最大 65536 字节，用于完整 UDP 包。`request_id` 在节点/运行范围内幂等；报告为单调累计值，封存后不得增加。已发出的预留只有节点先持久化封存，才允许归还未用部分。

`settle_only:true` 不发放新额度，但返回已经发出而响应可能丢失的预留；尚未发放的请求会记录取消状态，即使原请求随后到达也不再分配。已停用规则的待确认请求同样需要结算。Agent 收到旧请求的预留后，先持久化封存，再用下一轮报告归还。新增字段使用默认值便于缺省解析，但 0.3.0 严格 JSON 客户端不接受 0.4.0 新字段，因此控制器与 Agent 应协调升级。

创建额度和恢复的完整约束见 [BUDGETS.md](BUDGETS.md)。当前未提供额度删除、周期清零或 HTTP 恢复解除接口；`allocation_paused:true` 时不发放新预留。0.4.0 的离线 `relay restore` 只有在完整恢复日志校验和重放成功后，才恢复原分配状态，见 [RECOVERY.md](RECOVERY.md)。接口的可用能力目录不表示完整灾难恢复已经完成。

`/recovery` 的 `head` 包含 `journal_id`、`schema`、`schema_sha256`、`sequence`、`sha256` 和 `committed_bytes`。这里的 `schema` 是恢复日志格式（0.20.0 仍为 4），不是 SQLite 应用 schema；后者由 `relay build-info` 的 `controller_schema` 报告，0.20.0 为 5。它不返回日志内容、磁盘路径或凭据。未认证的 `/healthz` 在恢复写入故障后返回 503 及 `status:recovery_log_unavailable`；正常为 200。该检查判断本机日志写入状态，不代表已完成异地备份或业务线路健康。

401 表示凭据失效；403 表示权限或归属错误；不可见节点返回 404；400/422 表示输入不合法；409 表示版本/账本冲突；412 表示恢复分页期间配置变化。内部错误返回通用消息，细节进入本地服务日志。

0.5.0 的 `/agent/sync` 在控制器内最多等待 2 ms 合并，单批最多 16 项，等待队列最多 64 项；不是客户端批量接口。满队列返回 429，未入队请求不执行写入。认证、账本和额度检查仍在每项请求的事务保存点内执行；预期输入错误只回滚该项，磁盘或日志错误使整批不返回成功。响应丢失后继续使用原来的幂等请求 ID。管理员其他写入继续独立提交。

0.19.0 的 Agent 在同步循环之外保持一个 `/agent/watch` 长轮询。配置发布事务提交后控制器立即唤醒等待中的请求，Agent 随即同步、应用，并在应用成功（或出现新的应用错误）后马上再同步一次上报回执，不等下一个 `poll_seconds`。该接口只返回修订号，不返回配置、不写数据库、不需要执行租约。旧控制器没有此接口时，Agent 按 `poll_seconds` 退避重试并继续原来的轮询。

`/control/metrics` 字段为 `committed_batches`、`processed_requests`、`largest_batch`、`queue_full_rejections`、`failed_batches`、`batch_limit`、`queue_capacity`、`coalesce_window_ms`。计数在控制器重启时清零，不是流量账本；`processed_requests` 包含完成校验后返回预期错误的请求，整批提交失败单独计入 `failed_batches`。没有数据变更的批次可以不产生日志记录。`/usage` 在上报时间相同的情况下，再按节点、规则、周期稳定排序。

## 0.6.0 路由字段

规则新增可选 `listen_end_port`、`port_mapping`、`outbound_bind`、`dns_cache`；完整合同及示例见 [ROUTING.md](ROUTING.md)。旧字段默认值保持兼容，SQLite schema 仍为 v4。0.5 Agent 会拒绝带新字段的配置，因此先升级节点，再发布新能力。IPv6 监听现在明确设为仅 IPv6，双栈需要两条监听规则。

## 0.7.0 PROXY 字段

规则新增 `inbound_proxy={version,trusted_sources,placement,max_header_bytes}`；每个目标新增 `proxy_protocol={version,placement,checksum}`。字段、默认值、TLS 顺序、可信对端与来源 ACL 的区别、UDP 逐包语义见 [PROXY.md](PROXY.md)。未知字段和不支持的协议组合会被拒绝；节点实际应用失败继续通过 `apply_error` 返回。SQLite schema v4 不变，0.6 Agent 应先升级再发布新字段。

能力目录新增 `proxy-protocol-tcp-v1-v2`、`proxy-protocol-udp-v2`、`udp-destination-tracking`。它们表示代码实现能力，不表示已经通过 Linux、外部 UDP/TLS 互通或生产压力验收。

## 0.19.0 Shadowsocks 字段

规则新增 `inbound_shadowsocks={method,password,allow_private_destinations}`，缺省表示关闭；启用时 `protocol` 可为 `tcp`、`udp` 或 `both`（UDP 为 0.19.0 后续加入，旧版 Agent 上只能用 `tcp`），`targets` 必须为空，不能与入口 TLS、入口 WebSocket、多路聚合或健康检查同时使用。方式、密钥格式、内网目的地策略和拒绝行为见 [SHADOWSOCKS.md](SHADOWSOCKS.md)。旧版 Agent 不接受新字段，应先升级节点再发布。

## 0.8.0 WebSocket 字段

规则新增 `inbound_websocket={path,host,allowed_origins}`；每个目标新增 `websocket={path,host,origin}`，缺省表示关闭。两端必须协商 `relay-stream-v1` 子协议。仅 TCP，组合相同方向的 TLS 字段即为 WSS；Host、Origin、路径、二进制记录、半关闭、限额和 PROXY 顺序见 [WEBSOCKET.md](WEBSOCKET.md)。控制器发布时执行结构校验，节点继续执行监听与本地 TLS 材料预检；失败不替换旧版本。

能力目录新增 `websocket` 和 `secure-websocket`，页面提供入口及逐目标编辑字段。SQLite schema v4 与恢复日志不变，0.7 Agent 不接受新字段，应先协调升级。能力目录并不声明任意第三方 WebSocket 隧道兼容或完整安全模块验收通过。

## 0.9.0 多跳与配置批次

规则可声明 `advertise`（其他节点实际可达的 host:port），目标可带 `via={node_id,rule_id}`。引用必须与实际目标地址、租户、协议及传输组合相符，声明图必须无环；已知端点不能仅去掉 `via` 绕过校验。没有自动解析 DNS/NAT 别名或证明网络可达性。

预览和发布都返回 `{configs,changes}`。每个 change 包含 `node_id,from_revision,to_revision,added,modified,removed,rule_changes`；每条 rule_change 为 `{rule_id,before,after}`，新增的 before 或删除的 after 为 null。预览不修改修订、绑定、审计或日志；发布重新执行全部检查。节点修订冲突返回 409，非法引用/协议/环路返回 400，HTTP 请求上限 2 MiB。提交完整的规则列表，省略既有规则表示删除。

改变已启用拓扑规则的路由结构必须先按原结构停用，再等节点确认该版本、无应用错误且全部活跃 TCP/UDP 会话及探测数归零；在此之前改向、删除、重新启用或换规则 ID 复用监听都返回 409。单节点 PUT 与历史回滚使用相同检查。节点尚未注册时可以提前编辑。

控制器原子提交配置、历史、绑定和审计，但节点应用是异步的。`/topology` 的 `activation` 固定为 `asynchronous-per-node`，节点列表包含 `desired_revision,applied_revision,apply_error,stats,last_seen_ms,enrolled`。单个节点准备失败仍保留旧版本，必须检查逐节点回执。详细合同和计量方式见 [TOPOLOGY.md](TOPOLOGY.md)。能力目录新增 `declared-multi-node-topology` 和 `atomic-config-batch`；schema v4 不变，先升级所有相关 Agent 再发布新字段。

## 0.10.0 目标健康与选择

规则新增可选 `health_check`，逐目标新增 `priority`（缺省 0，越小越优先）和 `max_sessions`（缺省不设单目标上限）。目标还可设 `paused`（硬暂停）和 `paused_until_ms`（到期自动恢复的 Unix 毫秒时间，须与 `paused` 同时出现）；`balance` 另接受 `random`（最高可用优先级内均匀随机，忽略权重）。健康检查必须覆盖规则的实际 TCP/UDP 协议；请求/预期内容使用有界 Base64。状态机、恢复等待、端口映射、目标容量作用域、实际出口和探测计量见 [HEALTH.md](HEALTH.md)。

同步 stats 新增可省略的 `active_probes` 和 `target_health`。控制器将报告与该节点 `applied_revision` 的配置比较，再接受整项同步；无效健康报告返回 400，同项用量也不提交。报告仅供诊断，不承担业务计费或额度归还职责。

`GET /nodes/{id}/health` 返回 `{node_id,applied_revision,desired_revision,apply_error,last_seen_ms,active_probes,expected_endpoints,rule_names,reports}`。报告字段见 HEALTH.md；读取时为采样年龄加上最后心跳后的时间，过期报告显示 stale，不覆盖数据库原始样本。节点未上报或返回空列表时不可推定健康。所有计数表示最后一次节点采样。

能力目录新增 `target-health-checks` 和 `priority-capacity-selection`。目标健康页面与规则编辑器使用相同模型。schema v4 保持不变，需协调升级控制器和 Agent，再启用新字段；成本/延迟自适应调度及跨节点容量租约仍未完成。

## 0.11.0 计量与同步耗时

节点同步 stats 增加可选 `meter`，经现有 `/nodes` 返回；老节点缺省为 null/不提供，不能推断为零等待。新 Agent 总是发送此字段，因此先升级控制器再升级 Agent。SQLite schema v4 不变。

`meter` 包含 `admission_batches,admission_requests,failed_batches,budget_wait,budget_waiting,budget_timeouts`。其中 admission_batches 与 budget_wait 是 `{samples,total_us,max_us}`。控制器 `/control/metrics` 新增相同计时结构的 `queue_time,storage_batch_time,request_time`，仍仅允许系统管理员访问。完整边界、失败采样、并发快照和计时单位见 [DIAGNOSTICS.md](DIAGNOSTICS.md)。

这些数据用于运行诊断，不能替代累计业务账本或触发退款。接收同步回复时，Agent 将用量确认与预算回复在一次本地事务内提交，非法后续回执不会提前确认前面的用量；失败请求可按原身份重试。

## 0.12.0 多路径字段与诊断

规则增加 inbound_multipath / outbound_multipath，参数、默认值及窗口/方向限制见 [MULTIPATH.md](MULTIPATH.md)。继续使用现有单节点配置、多节点预览/发布、历史和回滚接口及权限，没有旁路接口或私钥上传。已声明路径必须通向同一汇聚规则，匹配 mTLS/WS/PROXY、路径上限与复制授权；固定端口段可引用其段内端口。

节点 stats.multipath 提供本次进程聚合会话、子流、负载、复制、重传、重复接收及窗口峰值，8 个槽位在节点各规则间汇总；旧报告没有此字段时视为缺失。排空要求聚合会话/子流也为零。新增诊断会使旧控制器拒绝新 Agent，应先升级控制器。节点有序停止会至少尝试一次最终状态同步，保留最近配置应用错误；超时不意味着服务器已确认。

## 0.13.0 节点执行租约

HTTP 创建节点时省略 lease_policy 默认严格 30 秒；对象 {"ttl_ms":5000} 可指定 5～120 秒，null 明确选择离线。已有节点维持离线策略，策略创建后固定。节点列表新增 lease 状态，active 表示服务端仍保留所有权，不能替代业务健康检查。

Agent 的 POST /agent/lease 接收 run_id、随机 token、generation；generation=null 申请，当前代数续租。POST /agent/lease/release 接收 proof 与零活跃 stats。均使用节点 Bearer。严格节点的同步/对账请求必须增加 lease={run_id,generation,token}，预算 run_id 必须一致。缺少证明返回 423，过期或不匹配返回 409；不改变此前账本去重口径。

能力目录新增 node-execution-leases。详细字段、截止期、恢复等待、异常退出及先升级控制器的约定见 [NODE_LEASES.md](NODE_LEASES.md)。schema 仍为 v4，不代表可以直接将正在使用严格模式的控制器降级。

## 0.14.0 原状态额度恢复与预留明细

POST /agent/lease 新增可选 resume_generation；只有 generation=null 且原 run_id/代数仍是控制器最后持有者时才允许恢复领取。历史不连续返回 412，Agent 使用新的 run_id 和 token 申请普通租约，旧预留保守保留。

POST /agent/budgets/recover 仅接受节点 Bearer，输入为 {lease,ledger_id,run_id,claims,requests}。claims 每项为 {grant,consumed_bytes,sealed}，grant 仍为完整的 {grant_id,budget_id,request_id,run_id,bytes}；requests 使用原 GrantRequest。每项请求最多 512 份 claim 和 512 个待确认请求，仍受 2 MiB HTTP 上限约束。它要求有效严格租约、此次所有权具有恢复来源、匹配对账账本、未隔离的控制器和连续的消费边界。全部本页校验通过才在一个事务内补报；返回 BudgetReply，不发放新的预留。已发放但回复丢失的请求返回原 grant，未发放的请求被取消。详见 [BUDGET_RECOVERY.md](BUDGET_RECOVERY.md)。

GET /budgets/{id}/reservations?after=grant_id 使用用户会话，按预算所属租户检查权限，允许该租户只读角色。每页最多 100 条开放预留，返回 {budget_id,reservations,next}；next 为下一次 after，null 表示本页没有更多。每项包含 grant_id、node_id、node_name、run_id、allocated_bytes、confirmed_consumed_bytes、outstanding_bytes 和当前 node_lease。外租户或不存在的预算返回 404；非法游标、未知查询字段返回 400。列表为实时键集分页，多页不是同一事务快照；outstanding_bytes 包含尚未上报消费，不能直接退款。

节点 stats 新增可选 budget_recovery={run_id,at_ms,validated_grants,recovered_pending_grants,cancelled_requests,open_grants}，表示本次进程启用监听前的恢复结果。open_grants 为当时仍可消费的预留数量，不是当前余额。能力目录新增 durable-budget-run-recovery。schema v4 不变；先升级控制器，再升级 Agent，旧控制器不能直接读取新增恢复租约元数据或接收新诊断字段。

## 0.15.0 节点资料与生命周期

节点列表新增 profile={revision,updated_at_ms,settings} 和 lifecycle=active/disabled/expired。资料字段、成本整数口径、筛选、全量更新和批量事务见 [NODE_MANAGEMENT.md](NODE_MANAGEMENT.md)。读写沿用租户边界；只读角色写入 403，外租户节点 404，资料版本冲突 409。

严格节点暂停后，领取/续租返回 403；到期后返回 410。到期前租约 valid_for_ms 被剩余时间截短，ttl_ms 仍表示策略上限。暂停和到期不阻止尚有效证明的结算，也不自动退还未知余额。离线节点设置暂停/到期返回 400；生效窗口与不能倒改已授截止时间的 409 条件见节点管理文档。

能力目录新增 node-inventory-lifecycle。schema v4 保持不变；旧控制器没有这些生命周期检查，不能直接降级仍在依赖这些约束的状态。

## 0.19.0 两步验证与 API 令牌

`POST /auth/login` 新增可选 `second_factor`（6 位验证码或恢复码，最长 32 字节）。账号已启用两步验证而未提供时返回 401 `{error:"two-factor code required",second_factor_required:true}`；验证码错误返回 401 `invalid two-factor code`。只有密码正确才会出现这两种回复。同一账号 5 分钟内 10 次错误验证码后返回 429，与原有按来源地址的登录限次分别计算。

| 方法 | 路径 | 请求或用途 |
| --- | --- | --- |
| GET | `/account/mfa` | `{enabled,pending,recovery_codes_remaining}` |
| POST | `/account/mfa/setup` | `{password}` → `{secret,otpauth_uri,qr_svg}`；生成待确认密钥，登录行为不变；已启用时 409 |
| POST | `/account/mfa/enable` | `{code}` → `{recovery_codes}`；8 个恢复码只返回这一次 |
| POST | `/account/mfa/disable` | `{password,code}`；code 可为验证码或恢复码 |
| POST | `/users/{id}/mfa/reset` | 管理员重置他人两步验证，并撤销其会话与令牌；不能用于自己（400） |
| GET / POST | `/api-tokens` | 列出自己的令牌（不含秘密）；`{name,scopes,expires_in_days}` 创建，返回 `{token,api_token}` |
| DELETE | `/api-tokens/{id}` | 撤销自己的令牌 |

API 令牌使用同一个 `Authorization: Bearer` 头，格式为 `rpat_` 加 64 位十六进制，服务端只保存 SHA-256 哈希。`scopes` 取值：`read`（所有 GET）、`nodes:write`（节点、配置、凭据操作与配置批次）、`budgets:write`、`users:write`（用户、租户、撤销会话）。范围不足返回 403；实际权限仍受账号角色和租户限制，只读用户的写入范围不产生写权限。`/account/*`、`/api-tokens*`、`/users/{id}/mfa/reset` 和 `/auth/logout` 只接受登录会话。有效期 1..365 天，每个用户最多 20 个未过期令牌；`/users/{id}/revoke-sessions` 同时撤销该用户的令牌。

`/users` 每项新增 `mfa_enabled`。审计新增 `mfa.enable`、`mfa.disable`、`mfa.reset`、`mfa.recovery_code_used`、`api_token.create`、`api_token.revoke`。能力目录新增 `two-factor-login` 和 `scoped-api-tokens`。两类状态保存在 metadata 中并进入恢复日志；0.19.0 仍声明 schema v4，回退到 0.18.0 控制器会忽略两步验证。0.20.0 起应用 schema 升至 v5、状态兼容代号升至 2，旧二进制与安装器回滚均被拒绝，见下节。

## 0.19.0 遥测

0.19.0 的 Agent 在每次同步的 `stats` 中附带 `system`：`cpus`，以及可选的 `cpu_percent`（整机，两次同步之间的占用 0..100）、`process_cpu_percent`（本进程，按单核计，可超过 100）、`rss_bytes`、`memory_total_bytes`、`memory_available_bytes`、`load_1m`。只在 Linux 上从 `/proc` 读取，其他平台只报 `cpus`。控制器丢弃不合理的取值而不是截断。`EngineStats` 拒绝未知字段，所以旧控制器会拒绝新 Agent 的同步：**先升级控制器，再升级 Agent**。

`GET /telemetry` 返回：

```json
{
  "generated_at_ms": 0,
  "window_ms": 3600000,
  "offline_after_ms": 30000,
  "nodes": [{"id": "…", "name": "…", "last_seen_ms": 0, "enrolled": true, "samples": [
    {"at_ms": 0, "forwarded_bytes": 0, "active_sessions": 0, "failed_connections": 0,
     "cpu_percent": 3.5, "process_cpu_percent": 0.4, "rss_bytes": 0,
     "memory_total_bytes": 0, "memory_available_bytes": 0,
     "probe_latency_us": 812, "healthy_targets": 3, "probed_targets": 4}
  ]}],
  "events": [{"id": 1, "at_ms": 0, "node_id": "…", "severity": "warning", "kind": "target_down", "subject": "web/0/8443/TCP", "message": "…"}]
}
```

每次成功提交的同步记录一个采样，每节点最多 20000 个、最长 24 小时。`forwarded_bytes` 是 Agent 进程启动以来双向转发字节累计，Agent 重启后归零，速率应按相邻采样差值计算并把负差值视为重启。`probe_latency_us` 是当前可选目标最近探测耗时（EWMA）的中位数，是节点到目标的探测往返，不是中转增加的延迟。`severity` 为 `info`、`recovered`、`warning`、`critical`；`kind` 为 `target_down`（由可用变为不可用，或首次出现时就不可用，包括控制器重启后的第一次回报）、`target_recovered`、`target_removed`（不可用的目标从配置中移除）、`config_rejected`、`config_recovered`、`config_applied`、`node_reconnected`（超过 30 秒无回报后恢复），以及读取时生成的 `node_offline`（已注册节点超过 30 秒无回报，`id` 为 0）。事件全局最多保留 500 条，按时间升序。`subject` 是事件在节点内的对象，目标事件为 `规则/目标序号/监听端口/协议`，其他事件为空字符串；同一目标的下线、恢复与移除事件 `subject` 相同。

采样和事件只保存在控制器内存，控制器重启后从空开始；不进入恢复日志，不作为计量、计费或配额依据。权限与 `/nodes` 相同：只读用户可查看本租户，系统管理员可查看全部。


## 0.132.0 实时日志与诊断报告

每个进程把通过日志过滤（默认 `info` 及以上）的日志行复制到内存中的环形缓冲，保留最近 2000 行，每行最多 1000 个字符。控制器在同步回复中返回 `log_cursor`（它持有的该节点最后一行：`stream` 为 Agent 本次运行的随机标识，`seq` 为行号），Agent 在下一次同步的 `logs` 中发送其后的行，每次最多 200 行、64 KiB。Agent 只在收到 `log_cursor` 之后才发送 `logs`，所以旧控制器不会收到这个字段，升级顺序不受限制；旧 Agent 忽略 `log_cursor`。

```json
{"logs": {"stream": "3f0c…", "lines": [
  {"seq": 41, "at_ms": 0, "level": "warn", "text": "configuration rejected; retaining previous revision message=cannot stage TCP listener 127.0.0.1:9000"}]}}
```

控制器在内存中为每个节点和自己（来源 `controller`）各保留最近 2000 行，不写磁盘；控制器重启后从新的日志开始。重发的行按 `seq` 去重。`stream` 变化表示 Agent 重新启动，该来源的第一行带 `"restarted": true`；同一次运行中缺少的行（Agent 缓冲溢出）在下一行以 `"missing": N` 标出。系统日志（journalctl）仍是完整记录。

`GET /logs?source=…&after=ID` 仅系统管理员可用（只读令牌须属于系统管理员），返回 `id` 大于 `after` 的行，按到达顺序，最多 500 行；更多时返回最新的 500 行并设 `truncated: true`。`id` 跨来源递增，面板以上次的 `latest_id` 作为下一次的 `after`。`latest_id` 变小表示控制器已重启。

```json
{"lines": [{"id": 1201, "source": "<node id>", "at_ms": 0, "level": "info", "text": "controller connection recovered"}],
 "truncated": false, "latest_id": 1201,
 "sources": [{"id": "controller", "name": "controller"}, {"id": "<node id>", "name": "hkg-entry-01", "enrolled": true}]}
```

`GET /diagnostics/report` 仅系统管理员可用，返回 `format: "relay-diagnostics/1"` 的 JSON：

- `findings`：按严重程度排序的问题，每项含 `severity`（`critical` / `warning` / `info`）、`kind`、相关的 `node` / `rule`、数值 `facts` 和中文 `message`。`kind` 包括 `node_offline`（超过 30 秒无回报）、`node_never_reported`、`node_not_enrolled`、`config_rejected`、`config_pending`、`hop_failing`（最近 1 小时至少 5 次连接且成功率低于 90%，低于 50% 为 `critical`；`facts.cause` 为最多的失败原因）、`target_unhealthy`（探测不健康且该段没有 `hop_failing`；同一目标的 TCP / UDP 探测合并为一项，`facts.probes` 列出各协议的错误）、`high_cpu`（≥ 90%）、`low_memory`（可用低于 10%）、`log_errors`（最近 1 小时有错误行）和 `log_warnings`（最近 1 小时至少 10 条警告）。离线节点只报告离线，其他数据已过时。
- `summary`、`nodes`（回报时间、修订、应用错误、系统资源、连接计数、目标探测）、`connections_last_hour`、`events`（最近 24 小时，最多 200 条）、`logs`（每个来源最近 300 行）。
- `rules` 只包含 ID、名称、启用、协议、监听与公开地址、负载均衡、超时与限额，目标的地址、下一跳、权重、优先级以及 `tls` / `proxy_protocol` / `websocket` 是否启用；其他设置只列出字段名（`features`）。报告不包含密码、密钥、令牌、证书或所有者。日志行与服务器地址会出现在报告中。

## 0.131.0 连接记录与 7 天历史

Agent 在同步的 `stats.connections` 中按规则逐段报告真实 TCP 连接的结果，数值为 Agent 进程启动以来的累计，没有记录时省略：

- 省略 `target_index`：规则的入站一侧。被接受的连接完成入站 TLS、PROXY、WebSocket 设置记一次成功，期间失败记一次失败；被来源 ACL 拒绝的连接、规则更新时取消的连接不计。预热连接在客户端到达之前的等待不计。
- `target_index` 为数字：拨号到该目标，`target_address` 为配置中的地址。每次完成的拨号记一次，包括并行补拨中先完成的一次；因另一目标先连通而被取消的补拨不计。没有可选目标、因而没有拨号的连接不出现在这里，其原因见目标探测。

```json
{"rule_id": "web", "target_index": 0, "target_address": "203.0.113.7:443",
 "counts": {"attempts": 120, "connected": 118, "timeout": 1, "refused": 1, "dns": 0,
            "closed": 0, "other": 0, "connect_us": 2360000}}
```

失败原因之和等于 `attempts - connected`：`timeout` 超时，`refused` 被拒绝，`dns` 域名解析失败，`closed` 建立过程中被对端关闭或重置，`other` 其他（TLS、协议或策略错误）。`connect_us` 是成功拨号的建立耗时之和。UDP 不计。目标地址修改或规则删除后，对应计数从报告中移除。`EngineStats` 拒绝未知字段，旧控制器会拒绝带此字段的同步：先升级控制器再升级 Agent，回退时先回退 Agent。

控制器把相邻两次回报的差值和每次回报的吞吐、会话、探测往返、CPU 累加到 5 分钟桶，每分钟写入状态目录下的 `history.sqlite`（权限 0600），保留 7 天。该文件独立于 `controller.sqlite`，不进入备份和恢复日志，丢失只影响图表。控制器启动后每个节点的第一次回报只作为基准；计数回退视为 Agent 重启，按从零开始计算。服务正常停止时会写入最后一分钟，异常退出最多丢失 1 分钟。

`GET /history?range=…` 的权限与 `/telemetry` 相同，只读令牌可用。`1h` 合并为一格，`24h` 每 15 分钟一格，`7d` 每小时一格；区间结束于当前 5 分钟桶的末尾，所以最后一格仍在累计。

```json
{
  "generated_at_ms": 0, "start_ms": 0, "end_ms": 0, "step_ms": 900000,
  "nodes": [{"id": "…", "name": "…", "bins": [
    {"at_ms": 0, "reports": 180, "forwarded_bytes": 0, "sessions_sum": 0, "sessions_max": 0,
     "latency_sum_us": 0, "latency_count": 180, "healthy_sum": 0, "probed_sum": 0,
     "cpu_sum": 0.0, "cpu_count": 180}]}],
  "hops": [{"node_id": "…", "rule_id": "web", "target_index": 0, "target_address": "203.0.113.7:443",
    "bins": [{"at_ms": 0, "attempts": 120, "connected": 118, "timeout": 1, "refused": 1,
              "dns": 0, "closed": 0, "other": 0, "connect_us": 2360000}]}]
}
```

节点格是格内各次回报的和：平均会话为 `sessions_sum / reports`，平均探测往返为 `latency_sum_us / latency_count`，`forwarded_bytes` 是格内转发的字节。没有数据的格不返回。只由控制器服务保存历史；其他方式打开的数据库返回 404。

## 0.19.0 告警通知

控制器每 2 秒读取新的遥测事件和节点回报时间，把问题归为告警（incident），再通知已启用的通道。三类问题：

| 告警 | 级别 | 开始 | 结束 |
| --- | --- | --- | --- |
| `target:{节点}:{subject}` | `warning` | `target_down` | `target_recovered` 或 `target_removed` |
| `config:{节点}` | `critical` | `config_rejected` | `config_recovered` |
| `node:{节点}` | `critical` | 已注册且允许运行的节点超过 30 秒无回报 | 恢复回报，或节点被暂停、到期、撤销身份 |

- **分组**：新问题等待 5 秒再通知，同一时刻需要发给某个通道的所有开始与恢复通知合并为一条消息，最多列出 10 条（新问题和严重级别在前），其余计数。只有一条时按单条格式发送。
- **合并**：同一告警恢复后 5 分钟内再次出现，仍是原告警，`repeats` 加一。距上一条通知不足 5 分钟时不再发送开始通知；5 分钟后仍未恢复则再发一次，并写明反复次数。
- **恢复通知**：只在开始通知已经发出时发送，所以在保持期内短暂出现又消失的问题不会产生任何通知。
- **维护模式**：`maintenance_until_ms` 之前不发送开始通知；维护结束时仍未恢复的告警会补发。维护期间出现又恢复的问题不通知。
- **重试**：发送失败（非 2xx，或企业微信/钉钉 `errcode≠0`、飞书 `code≠0`、Telegram `ok:false`）后在 10 秒、60 秒、300 秒后重试，每次请求超时 10 秒。
- **级别**：通道 `min_severity` 为 `warning`（全部三类）或 `critical`（仅配置拒绝和节点离线）。

`target` 按 `kind` 取不同字段：

| kind | 字段 | 发送方式 |
| --- | --- | --- |
| `webhook` | `url`，可选 `secret` | POST `{"sent_at_ms","text"}`；有密钥时加 `X-Relay-Signature: sha256=<正文 HMAC-SHA256 十六进制>` |
| `telegram` | `bot_token`、`chat_id` | Bot API `sendMessage` |
| `wecom` | `url` | 企业微信群机器人文本消息 |
| `feishu` | `url`，可选 `secret` | 飞书自定义机器人；有密钥时按飞书规则加 `timestamp`（秒）和 `sign` |
| `dingtalk` | `url`，可选 `secret` | 钉钉自定义机器人；有密钥时在地址上加 `timestamp`（毫秒）和 `sign` |

`GET /alerts` 返回：

```json
{
  "settings": {"maintenance_until_ms": null},
  "channels": [{"id": "…", "name": "值班群", "enabled": true, "min_severity": "warning",
    "kind": "dingtalk", "destination": "https://oapi.dingtalk.com/…", "secret_set": true}],
  "incidents": {
    "open": [{"key": "target:…:web/0/8443/TCP", "node_id": "…", "node_name": "hkg-entry-01",
      "severity": "warning", "summary": "…", "opened_at_ms": 0, "resolved_at_ms": null,
      "repeats": 0, "notified": true, "last_notice_ms": 0}],
    "resolved": [],
    "deliveries": [{"id": 1, "channel_id": "…", "channel_name": "值班群", "incident_key": "…",
      "incidents": 1, "notice": "opened", "created_at_ms": 0, "attempts": 1, "status": "sent", "error": null}]
  }
}
```

`incidents` 是这条消息包含的告警数，分组消息的 `incident_key` 是其中第一条；`notice` 为 `opened`（含任何新问题）、`resolved`、`test`；`status` 为 `pending`、`retrying`、`sent`、`failed`。`resolved` 与 `deliveries` 各保留最近 200 条，新的在前。

通道与设置保存在 metadata 中，进入备份和恢复日志，schema v4 不变；最多 20 个通道。API 只返回地址的协议和主机，不返回令牌和密钥。只有系统管理员可读写；写操作只接受登录会话，API 令牌即使带写入范围也返回 403。审计新增 `alerts.settings`、`alerts.channel.create`、`alerts.channel.update`、`alerts.channel.delete`。能力目录新增 `alert-notifications`。

限制：告警状态和发送记录只在控制器内存中，重启后清空；重启后的第一次回报会重新检测不可用的目标，节点离线在启动 60 秒后才判定。通知地址由系统管理员填写，控制器会向其发起请求，包括内网地址，所以只应授予可信管理员。邮件通道、按租户分别配置告警、只读诊断角色和告警自动化动作尚未实现。

## 0.20.0：状态兼容围栏与限速修复

`relay build-info` 现在报告 `controller_schema: 5` 和 `state_contract: {controller: 2, agent: 2}`。控制器与 Agent 数据库的 `PRAGMA user_version` 从 4 升至 5，表结构和恢复日志格式 4 不变；0.18.0/0.19.0 在打开数据库时以 `database schema newer than this binary` 失败，签名安装器也以状态兼容代号不一致拒绝回滚。`relay restore` 接受 schema v4 备份和仍为格式 4 的连续恢复日志，重放完成后把输出数据库升级到 v5。升级顺序仍为先升级控制器并启动一次以完成 schema 围栏，再升级 Agent；已有 0.19.0 状态在升级前不要回退到 0.18.0。

跨节点用户限速：

- 带 `advertise` 的规则不再被排除在用户份额之外。广告地址可被直接访问，拓扑声明本身不能证明上游已经计量，因此直接客户端同样受限。
- 控制器的分享列表按每节点“期望修订 ∪ 已应用修订”的规则计算；节点只有在报告新 `applied_revision` 后才退出旧规则的份额。
- Agent 在 `engine.apply` 失败时保留并续租原份额，不再套用失败修订返回的列表；同步响应字段不变。
- 同一用户流量经过多跳时，每一跳执行自己的份额，链路吞吐可能低于单节点份额；当前没有可信上游认证，不能只对入口计量。

Shadowsocks：TCP 重放盐缓存按（方式、密钥）在进程内共享。规则重命名、限速调整等不改变密钥的替换继续拒绝已捕获的请求；修改密钥后使用新的加密身份。UDP 关联在规则修改时仍按既有行为结束，已结束关联的包号记录保留 60 秒。

## 0.21.0 客户端订阅

订阅把用户自己的 Shadowsocks 入站规则快照成 V2Ray/Base64、Clash YAML、Surge 或 Shadowrocket 文本。管理接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/subscriptions` | 可见订阅列表；不返回令牌或哈希 |
| POST | `/subscriptions` | `{name,format,template,expires_in_days,user_id?,allow_sources?}` → `{subscription,token}`；令牌只返回一次 |
| GET | `/subscriptions/{id}` | 订阅元数据 |
| PUT | `/subscriptions/{id}` | `{name,format,template?,allow_sources?,expires_in_days?}`；修改设置，令牌不变 |
| GET | `/subscriptions/{id}/preview` | `{content,content_type,entries,skipped}`；普通 TCP/TLS/WS 规则明确列入 `skipped` |
| POST | `/subscriptions/{id}/rotate` | 可选 `{grace_minutes}`（0..1440）；新令牌，旧令牌立即或宽限期后失效 |
| DELETE | `/subscriptions/{id}` | 删除记录与索引 |
| GET | `/sub/{token}` | 公开端点，无登录；60 次/分钟/令牌；`Cache-Control: no-store` |

`format` 为 `v2ray`、`clash`、`surge`、`shadowrocket`。`template` 为 `{name_prefix,host,node_tags,udp}`，创建时保存为快照；`host` 覆盖连接地址，`node_tags` 过滤节点，通配监听且无 `advertise`/`host` 的规则会被跳过。端口段展开为多个条目。`surge` 返回完整的 Surge 托管配置，公开链接第一行为指向自身的 `#!MANAGED-CONFIG`。包含 Shadowsocks 入站和受管协议入口；其他规则，以及某格式无法表达的协议入口（`surge` 跳过 VLESS/Reality，`v2ray`、`shadowrocket` 跳过 AnyTLS），在预览的 `skipped` 中给出原因。可选的 `template.upstreams` 为用户自己的 SOCKS5/Shadowsocks 代理（最多 8 个），在 `sing_box`、`clash`、`surge` 中经中转条目组成代理链，预览条目带 `chained: true`；其他格式列入 `skipped`。见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)。

权限：读取列表/预览需要 `read`，创建/轮换/删除需要 `users:write`，并同时受账号角色与租户边界限制；只读用户不能写入。系统管理员可见全部，租户管理员可见本租户普通用户，普通用户只管理自己。令牌只保存 SHA-256 哈希；记录和索引写入 metadata，应用 schema 仍为 v5、恢复日志格式 4 不变。0.20.0 二进制忽略这些键，回退会丢失订阅服务但不会删除数据。详见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)。

## 0.22.0 DNS 托管记录与 DDNS

DNS 服务商、区域和记录保存在 metadata，schema 仍为 v5、恢复日志格式 4。所有 `/dns/*` 接口仅系统管理员，且只接受登录会话；API 令牌访问返回 403。服务商读取只返回 `token_set`，不返回令牌原文。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/dns/providers` | 服务商列表/创建 `{name,kind: cloudflare\|webhook,endpoint,token,min_ttl?,zones?,timeout_secs?}`；webhook 必须给出接收端 URL、至少 32 字节的 Secret（`token`）和 1–100 个 `zones`，`timeout_secs` 1–30（默认 15），同一 URL 409；协议见 [DNS.md](DNS.md#dns-webhook-服务商) |
| GET/PUT/DELETE | `/dns/providers/{id}` | 读取（脱敏）/更新（令牌留空保留，`min_ttl` 传 0 清除，webhook 可改 `zones`/`timeout_secs`，不接受 `kind`）/删除；有区域时 409 |
| POST | `/dns/providers/{id}/test` | 用已保存令牌列出可见区域 `{ok,zones:[{id,name}],truncated}`；webhook 发送签名 `ping`，返回配置的区域；失败 502，错误文本中的令牌替换为 `[redacted]` |
| GET/POST | `/dns/zones` | 区域列表（含内存中的 `status`）/创建 `{provider_id,name,mode,min_keep,failover_confirm_secs?}`（确认窗口 0..=1800 秒，省略为 60） |
| GET/PUT/DELETE | `/dns/zones/{id}` | 读取（含 `status`）/更新/删除；有记录时 409 |
| GET/POST | `/dns/zones/{id}/records` | 记录列表（含 `status`）/创建 `{name,type,content,ttl,proxied,health?}` |
| GET/PUT/DELETE | `/dns/records/{id}` | 记录读取（含 `status`）/更新/删除；应用模式删除时清理服务商记录 |
| POST | `/dns/zones/{id}/reconcile` | 观察或应用同步，返回创建/更新/删除/未变/保留/待确认（`pending`）/过半保护（`guarded`）/错误和逐条 action |
| POST | `/dns/records/{id}/ddns` | `{content}` 更新 A/AAAA 并同步；CNAME 返回 400 |

`mode=observe` 不写服务商，`apply` 只管理带 `relay:<record id>` 注释的记录。`min_keep` 在删除停用/健康摘除记录时保护当前有效托管记录数。记录的 `health:{node_id,rule_id}` 要求节点心跳不超过 90 秒且规则至少有一个 `eligible && healthy` 目标；否则观察模式给出 `would-health-remove`，应用模式摘除，恢复后重建。更新时 `clear_health:true` 移除门控。DDNS 不自动探测公网 IP；服务商只证明 API 接受，不证明 DNS 已传播。详见 [DNS.md](DNS.md)。

## 0.23.0 DNS 健康摘除

记录创建/更新可带 `health:{node_id,rule_id}`，同步器要求节点心跳不超过 90 秒、节点资料为活动状态，并且该规则至少有一个 `eligible=true` 且 `status=healthy` 的目标报告；否则观察模式报告 `would-health-remove`，应用模式删除服务商记录，恢复后下一次同步重建。更新时 `clear_health:true` 移除门控。`min_keep` 以“本地启用且健康门控通过”的记录数计算。健康门控测试直接写入真实 `nodes.stats_json` 结构，但没有启动真实 Agent 产生探测流量。

## 0.24.0 账号生命周期

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/account/password` | 本人改密 `{current_password,new_password}`；复核当前密码，保留当前会话、撤销其他 Web 会话 |
| POST | `/users/{id}/password` | 管理员重置密码 `{password}`；撤销目标全部 Web 会话和 API 令牌 |
| PUT | `/users/{id}/disabled` | `{disabled}`；停用撤销全部凭据，禁止停用自己，保护最后一个系统管理员 |
| DELETE | `/users/{id}` | 删除账号；禁止删除自己；目标有规则或订阅时 409；删除会话、令牌、MFA 和限速元数据 |

`/account/password` 只接受登录会话，API 令牌按 `account/` 前缀拒绝。`/users/*` 写入仍受角色、租户和 `users:write` 范围约束。密码 12..1024 字节。停用/启用不恢复旧会话或 API 令牌；删除用户前必须删除或转移其规则/订阅。用户列表新增 `disabled` 字段。

## 0.25.0 SOCKS5 入口

规则可增加：

```json
{"inbound_socks5":{"username":"user","password":"secret","allow_private_destinations":false}}
```

`username`/`password` 必须同时出现或同时省略（1..255 字节）。规则必须 `protocol=tcp` 且 `targets=[]`；不能同时设置 `inbound_shadowsocks`。只支持 CONNECT；BIND/UDP ASSOCIATE 返回 SOCKS5 状态 7。默认拒绝非公网目的地，测试可显式允许。可与入口 TLS/WebSocket/PROXY 组合。分享链接为 `socks5://[user:password@]host:port#name`。详见 [SOCKS5.md](SOCKS5.md)。

## 0.26.0 公告

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/announcements` | 当前账号可见的生效公告 |
| GET | `/announcements/manage` | 管理员列表；租户管理员含全局只读 |
| POST | `/announcements` | `{tenant_id,title,body,severity,starts_at_ms,ends_at_ms,enabled}`；全局仅系统管理员 |
| PUT/DELETE | `/announcements/{id}` | 编辑/删除，受租户边界约束 |

`severity` 为 `info`、`warning`、`critical`；标题 1..200 字节，正文最多 10,000 字节，`ends_at_ms` 必须晚于开始或为空。读取需要 `read`，写入需要 `users:write`，并受账号角色约束。记录在 metadata，schema v5、恢复日志格式 4 不变。详见 [ANNOUNCEMENTS.md](ANNOUNCEMENTS.md)。

## 0.27.0 套餐、钱包与订单

金额以人民币分（`i64`）保存，固定 `CNY`。所有 `/commerce/*` 仅登录会话，API 令牌访问 403。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/commerce/gift-codes` | 管理员礼品码列表/创建；普通用户 403 |
| PUT/DELETE | `/commerce/gift-codes/{id}` | 管理员编辑/删除；已兑换删除 409 |
| POST | `/commerce/gift-codes/redeem` | 用户兑换 `{code}`，直接入钱包；每用户每码一次 |
| GET/POST | `/commerce/coupons` | 管理员优惠码列表/创建；普通用户 403 |
| PUT/DELETE | `/commerce/coupons/{id}` | 管理员编辑/删除；已有使用 409 |
| GET/POST | `/commerce/plans` | 启用套餐列表（管理员含停用）/创建；写仅系统管理员 |
| PUT/DELETE | `/commerce/plans/{id}` | 编辑/删除；有订单时删除 409 |
| GET | `/commerce/wallet` | 自己的余额与流水 |
| POST | `/commerce/wallets/{user}/adjust` | 管理员 `{delta_cents,reference,description}`；引用唯一、余额非负 |
| GET/POST | `/commerce/orders` | 自己的订单（管理员全部）/创建 `{plan_id}` |
| POST | `/commerce/orders/{id}/pay` | 钱包支付，重复支付 409 |
| POST | `/commerce/orders/{id}/refund` | 管理员退款，重复退款 409 |

套餐/订单保存价格快照；优惠码订单保存 `subtotal_cents`、`discount_cents`、`coupon_code` 和最终 `amount_cents`。支付/退款不自动创建订阅、规则或流量权益。详见 [COMMERCE.md](COMMERCE.md)。

## 0.28.0 外部支付回调

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/commerce/orders/{id}/payment` | 创建/复用待支付外部支付意图；订单必须 pending |
| GET/PUT | `/commerce/webhook` | 管理员查看/设置 `{secret,enabled}`；读取只返回 `secret_set` |
| POST | `/commerce/payments/callback` | 无登录公开回调，HMAC-SHA256 验证原始请求体 |

回调 body：`{payment_id,status:"paid"|"failed",external_id,amount_cents}`；`X-Relay-Signature` 为原始 JSON 的 HMAC-SHA256 十六进制（可带 `sha256=`）。重复同状态回调幂等；金额不符/状态冲突/错误签名 4xx。外部支付成功订单 `channel=external`，钱包不变；钱包订单退款仍走 `/orders/{id}/refund`，外部订单该接口 409。其他 `/commerce/*` 仍仅登录会话。详见 [COMMERCE.md](COMMERCE.md)。

## 套餐流量周期与自动补流量

需要开启可选功能 `plan-entitlements`：关闭时套餐字段可以保存但不起作用，下表中的写接口返回 409。与其他 `/commerce/*` 一样只接受登录会话，API 令牌一律 403。业务规则见 [COMMERCE.md](COMMERCE.md#流量重置周期)，账本关系见 [BUDGETS.md](BUDGETS.md#套餐流量周期与自动补流量)。

套餐（`POST /commerce/plans`、`PUT /commerce/plans/{id}`，仅系统管理员）新增两个可选字段，PUT 省略时恢复默认：

| 字段 | 取值 |
| --- | --- |
| `traffic_reset` | `"none"`（默认）、`"billing"` 或 `{"every_days":N}`，N 为 1..366 |
| `top_up` | `null`（默认）或 `{"bytes":正整数,"price_cents":0..1000000000000,"max_per_cycle":1..1000}`；需要 `traffic_bytes` 且 `traffic_reset` 不是 `"none"` |

无效取值返回 400（套餐的其他校验错误也改为 400）。订单新增 `kind`（`"plan"` 或 `"top_up"`）以及 `traffic_reset`、`top_up` 快照；补流量订单由控制器创建，状态为 `paid`、`duration_days` 为 0、`traffic_bytes` 为补充量，`POST /commerce/orders/{id}/refund` 对它返回 409。补流量扣款出现在 `GET /commerce/wallet` 的流水里：`kind` 为 `purchase`，`reference` 为 `top_up:<用户>:<周期序号>:<次数>`。仍有效的套餐与要购买套餐的 `traffic_reset` 不同时，`POST /commerce/orders` 返回 409。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/commerce/entitlement` | 本人 | 自己的权益；无权益时为 `null` |
| GET | `/commerce/entitlements` | 系统管理员 | 全部权益 |
| POST | `/commerce/entitlements/{user}/activate` | 本人或系统管理员 | 等待额度的套餐立即生效 |
| PUT | `/commerce/entitlements/{user}/auto-top-up` | 本人或系统管理员 | 请求 `{"enabled":true\|false}`，返回权益；没有权益时 404 |
| POST | `/commerce/entitlements/{user}/reset` | 系统管理员 | 无请求体；立即开始新周期并返回权益。套餐不重置、已到期或分配处于恢复隔离时 409 |

权益对象新增 `auto_top_up`、`cycles`（已开始的周期数）和内部状态 `cycle`（`policy`、`anchor_ms`、`started_at_ms`、`baseline_bytes`、`allowance_bytes`、`top_ups`、`top_up_bytes`、`last_failure`）。套餐重置且未到期时还返回计算后的 `current_cycle`：

| 字段 | 含义 |
| --- | --- |
| `policy` | 本周期的 `traffic_reset` |
| `started_at_ms` / `ends_at_ms` | 周期开始；下次重置或到期，取先到者 |
| `next_reset_at_ms` | 下次重置；到期前不再重置时为 `null` |
| `allowance_bytes` | 每周期流量加本周期补流量；不限时为 `null` |
| `top_up_bytes` | 本周期补流量合计 |
| `used_bytes` | 本周期已上报的用量 |
| `reserved_bytes` | 节点已领取、尚未上报的预留 |
| `remaining_bytes` | 本周期还可分配的字节；不限时为 `null` |
| `top_ups` | 本周期补流量次数；上限是 `top_up.max_per_cycle` |
| `top_up` | 当前订单的补流量设置，未配置时为 `null` |
| `last_failure` | `{"reason","at_ms"}` 或 `null`；`reason` 为 `not_configured`、`switched_off`、`cap_reached`、`insufficient_balance` |

用户只能读取和切换自己的权益；租户管理员、只读用户和 API 令牌不能读取或修改他人的周期，也不能重置流量（403）。审计动作：`commerce.entitlement.reset`、`commerce.entitlement.auto_top_up`、`commerce.top_up`、`commerce.top_up.fail`。

## 0.29.0 工单

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/tickets` | 当前角色可见列表/创建 `{subject,body,priority}` |
| GET | `/tickets/{id}` | 工单与可见消息 |
| POST | `/tickets/{id}/messages` | `{body,internal}`；内部备注仅管理员 |
| PUT | `/tickets/{id}/status` | `open` / `pending` / `closed` |

普通用户仅自己的工单，租户管理员本租户，系统管理员全部；关闭后拒绝消息。`/tickets/*` 仅登录会话。详见 [TICKETS.md](TICKETS.md)。

## 0.32.0 HTTP CONNECT 入口

规则可增加：

```json
{"inbound_http_connect":{"username":"user","password":"secret","allow_private_destinations":false}}
```

仅接受 `CONNECT host:port HTTP/1.x`；可选 Basic 认证，缺失/错误返回 407，其他方法 405；默认拒绝非公网目的地。规则必须 `protocol=tcp`、`targets=[]`，不能同时配置 `inbound_shadowsocks`/`inbound_socks5`。连接成功后返回 200，失败 502。详见 [HTTP_CONNECT.md](HTTP_CONNECT.md)。

## 0.34.0 目的地 ACL

规则可选：

```json
{"allow_destinations":["*.example.com","10.0.0.0/8"],"deny_destinations":["secret.example.com"]}
```

支持 IP/CIDR/精确域名/`*.domain` 后缀/`*`；拒绝优先，空 allow 为全通。同时检查原始域名与解析 IP，适用于固定 TCP/UDP、Shadowsocks、SOCKS5 TCP、HTTP CONNECT、多路径和预热连接。非法模式在配置校验时拒绝。详见 [DESTINATION_ACL.md](DESTINATION_ACL.md)。

## 0.38.0 规则模板

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/templates` | 可见模板/创建 `{tenant_id,name,description,rule}` |
| PUT/DELETE | `/templates/{id}` | 编辑/删除，受租户范围 |
| POST | `/nodes/{node}/templates/{id}` | `{expected_revision,name,listen,variables?,template_version?}` 应用为新规则 |
| POST | `/nodes/{node}/templates/{id}/preview` | `{name,listen}` 只校验并返回拟创建规则 |
| POST | `/templates/{id}/rollout` | `{batch_size,canary_percent?,rollback_on_failure?,require_healthy?,require_target_health?,wait_for_apply_ms?,targets:[...]}` 有序发布并通过所选门控 |
| POST | `/templates/{id}/rollouts/{rollout_id}/retry` | 从原首批重新检查并恢复；已发布规则复用身份，成功记录幂等返回，并发重试 409 |
| GET | `/templates/{id}/versions` | 当前及历史模板版本 |
| GET | `/templates/{id}/diff?from=1&to=2` | 两版本的结构化差异 |
| POST | `/templates/{id}/versions/{version}/rollback` | 旧内容写为新版本，受当前及历史租户范围限制 |

0.97.0 批量结果：`applied` 仅表示已发布；`acknowledged/healthy/completed/reused` 分别表示精确修订回执、规则健康、通过所选门控、复用旧发布。回执和健康门控均拒绝被后续修订取代的配置。重试完整规则及旧记录兼容边界见 [TEMPLATES.md](TEMPLATES.md)。

模板创建/更新校验规则主体；应用生成新 ID、名称、监听和计量周期，走正常配置修订校验。`/templates*` 与节点模板应用仅登录会话。详见 [TEMPLATES.md](TEMPLATES.md)。

## 0.40.0 MPTCP 诊断

`GET /api/v1/diagnostics/mptcp`（仅系统管理员、登录会话）返回 `platform/supported/enabled/probe_error/interfaces/routes/endpoints/active_connections/note`。Linux 探测 MPTCP socket 与 `/proc` 配置；非 Linux 返回 `supported=false`。这是观测，不是数据面。CLI：`relay mptcp-info`。详见 [MPTCP.md](MPTCP.md)。

## 0.44.0 UPnP CLI

`relay upnp-map --description-url URL --internal-client IP --internal-port N --external-port N [--lifetime-secs N] [--delete]`：读取 IGD description，选择 WANIPConnection/WANPPPConnection，调用 SOAP AddPortMapping/DeletePortMapping；不做 SSDP 发现。无 HTTP API。详见 [NAT.md](NAT.md)。

## 0.43.0 PCP CLI

`relay pcp-map --gateway IP[:PORT] --internal-port N [--external-port N] [--lifetime-secs N] [--delete]`：PCP v2 MAP UDP 单映射客户端，随机 nonce、IPv4-mapped 外部地址、生命周期上限 7 天。无 HTTP API。详见 [NAT.md](NAT.md)。

## 0.42.0 NAT-PMP CLI

`relay nat-map --gateway IP[:PORT] --internal-port N [--external-port N] [--lifetime-secs N] [--delete]` 管理一个 NAT-PMP UDP 映射；默认端口 5351，生命周期上限 7 天，`--external-port 0` 由网关分配。无 HTTP API。详见 [NAT.md](NAT.md)。


## 0.113.0 managed HTTP/2 CONNECT

`Rule.inbound_http2_connect` enables the managed HTTP/2 path, requires `protocol="tcp"` and `targets=[]`, and supports Basic credentials, `bearer_token_sha256`, `max_concurrent_streams`, `allow_private_destinations` and optional `socket_buffer_bytes`. See [HTTP2.md](HTTP2.md) for defaults, bounds, TLS/ALPN, credential rotation, metering and client constraints. Statistics add `active_http2_streams`; Prometheus adds `relay_node_active_http2_streams`. Upgrade controllers first.

## 0.114.0 additions

Rules accept optional `mptcp: {inbound: "off|prefer|require", outbound: "off|prefer|require"}`. Live transport observations appear under `stats.mptcp`; see [MPTCP.md](MPTCP.md) for fallback semantics and the bound on observed sockets. Changing an active listener mode requires disabling and applying that rule first. SOCKS5 BIND peer sockets use the outbound policy.

SMTP targets use `{kind: "smtp", config: {...}}`. Channels accept optional `tenant_id`, and `GET /alerts` now permits tenant administrators with scoped results and `can_manage: false`. Mutations remain system-administrator session operations. SMTP passwords and full SMTP editing details are not exposed to tenant administrators. See [ALERTS.md](ALERTS.md).

## Managed protocol gateways (0.115.0)

Rules accept optional `protocol_gateway`: `{listen, protocol, security, allow_private_destinations}`. `listen` is the public endpoint; the enclosing rule's `listen` is a single loopback-only SOCKS bridge. Fixed targets must be empty. `protocol.type` is `vless`, `hysteria2`, `tuic`, `any_tls`, `trojan` or `vmess`. VLESS/VMess/TUIC require a non-nil UUID; Hysteria2/TUIC/AnyTLS/Trojan require a 16–256-byte password. VLESS accepts `vision`. AnyTLS currently requires rule protocol `tcp`; the other gateways accept `tcp` or `both`.

`security.type=certificate` requires a node-local `identity` and accepts optional client `server_name`. `security.type=reality` requires VLESS, `server_name`, `handshake` (host:port), `private_key` (32-byte base64url), and an even 2–16-digit hexadecimal `short_id`. Config access contains server secrets and follows existing rule configuration authorization. Subscription exports derive the Reality public key and never export its private key.

Gateway rules use the existing configuration/template APIs and rule policy fields. `EngineStats.protocol_gateway` reports `gateways`, `running`, `restarts`, `last_error`, `engine_version`, and local `process_id`. Engine binaries are selected only by node-local `RELAY_PROTOCOL_ENGINE` or deployment settings. The API cannot upload a binary or supply arbitrary engine configuration.

Subscriptions add format `sing_box`. Both `sing_box` and `clash` (mihomo/Clash Meta) render every managed gateway. `surge` renders VMess, Trojan, TUIC v5, Hysteria2 and AnyTLS, and `v2ray`/`shadowrocket` render the rule share links (VLESS/Reality, VMess, Trojan, Hysteria2, TUIC); the remaining combinations are reported in the preview's `skipped`. Set template `host` for wildcard public listeners. See [PROTOCOL_GATEWAYS.md](PROTOCOL_GATEWAYS.md) for source/license provenance, supported payloads and lifecycle limits.

## 0.119.0 Shadowsocks UDP-over-TCP

`inbound_shadowsocks` 新增 `udp_over_tcp`（boolean，缺省 false）。启用后需 `protocol=tcp` 或 `both`，接受 SagerNet UoT v1/v2；客户端必须显式启用同一扩展。普通 `ss://` 链接无法表达此选项，面板提供包含入口地址、出口凭据和 UoT v2 的 sing-box / Relay JSON，订阅的 sing-box 和 mihomo 格式也会写入相应选项。UoT 使用 TCP 连接数上限与活动计数，按 UDP 负载执行配额、速率、目的地 / 端口 ACL 和私网限制。原生 SS UDP 同时执行显式目的地 ACL。先升级 Agent 再发布。客户端半关闭补丁、源代码与使用步骤见 [SS_COMPATIBILITY_0.119.0_EN.md](SS_COMPATIBILITY_0.119.0_EN.md)。


## 0.121.0 UDP 客户端与监听就绪

面板及 sing-box 订阅的原生 SS UDP JSON 现在包含 `udp_fragment: true`；UoT 仍显式使用 v2，TCP-only 不添加 UDP 设置。随源码提供的 Relay SS 客户端也默认允许 SS UDP 分片，用户显式设置 `false` 时继续遵从。普通 `ss://` 无法表达分片或 UoT 选项。

CLI `reverse-mux-server --ready-file <新文件路径>` 在监听绑定和参数校验完成后生成权限 0600 的 JSON，报告实际地址、PID、版本和 `listeners_bound` 状态。支持 `:0`，避免先探测空闲端口再关闭造成的竞争；已有文件不会覆盖。消费者须等待完整 JSON 并核对存活 PID，业务连通仍须另测。详见 [0.121.0 guide](RELEASE_0.121.0_EN.md)。

随源码提供的 SS 客户端还修复了 SS2022 并发首包响应的 request-salt 竞争，避免有效 UoT 响应在首次写入尚未返回时被误拒绝。补丁包含三种 2022 算法的确定性回归测试。


## Automatic endpoint proposals (0.123.0)

Node `profile.settings.forwarding` optionally stores `{host, listen_ip?, port_start, port_end, public_port_start?}`. `host` is an IP or DNS name without a port; bracketed IPv6 is accepted. Automatic local ports default to 20000–29999 and must be at least 1024. `public_port_start` describes a pre-existing continuous provider NAT mapping; it never configures NAT. Omit it for identical public/local ports. Profiles are changed through the existing revision-checked node profile API and do not change published rules. `GET /topology` now includes each node's `profile` and `lifecycle`.

`POST /configurations/allocate-endpoints` accepts 1–16 distinct nodes in path order. All nodes must be writable and belong to the same tenant. Omit `listen` and `advertise` together for automatic assignment; supply both for a manual override. The response contains one endpoint proposal per hop, including `source` (`profile`, `existing_rule`, or `manual`), `defaults`, and `error` (`null`, `address_required`, `ports_exhausted`, or `port_in_use`). Missing node addresses are never guessed from node names or the controller hostname. An unambiguous existing rule endpoint may supply defaults; a single existing NAT mapping does not establish a mapped range.

Allocation conservatively avoids configured listeners, disabled rules, ranges, gateway ports/bridges, and public endpoints, including earlier proposals in the same request. Manual proposals are considered before automatic ones. It does not inspect arbitrary processes on the remote VPS or reserve ports. It returns the exact selected `configs` used for the calculation: build additive updates from these rules and revisions, validate with `/configurations/preview`, then publish the reviewed batch. A competing configuration publication invalidates a stale revision; reallocate and preview again. Aliased hostnames or Agents sharing a machine require correctly configured, non-overlapping ranges. Agent application and a traffic test are still necessary to confirm reachability.

## Optional features (0.135.0)

`GET /features` lists every optional feature as `{id, enabled, in_use}` for any signed-in role. `PUT /features/{id}` with `{"enabled": true|false}` switches one; it requires a system administrator session (API tokens are refused) and records `feature.enable` / `feature.disable` in the audit log. Unknown ids return 404. Switching off returns 409 while `in_use` is above 0.

`plan-entitlements` turns paid plan orders into the buyer's user budget; see [COMMERCE.md](COMMERCE.md). `budget-recovery` enables the write-off and restore-lock actions in [BUDGET_RECOVERY.md](BUDGET_RECOVERY.md). `mptcp-paths` lets node profiles carry `settings.mptcp_paths` for agents whose server opted in; see [MPTCP.md](MPTCP.md). `dns-authoritative` enables the authoritative DNS pool below; it stays on while any pool zone exists. `wireguard` enables the WireGuard networks below; it stays on while any network exists. Every feature starts off on a new controller. While a feature is off, changes that need it return 409: `mptcp` covers rules with a non-off MPTCP mode, and `dns-health` covers DNS records with a health gate. A controller upgraded with such settings already in place has no stored switch and reports the feature as on, so working configuration keeps running. The switches change controller validation and panel forms only; they never change server system settings.

## 0.137.0 Authoritative DNS pool

All routes need a system administrator session (API tokens are refused, as for every `/dns/` route). Creating or changing zones, name servers and records returns 409 while `dns-authoritative` is off; deletions always work. Validation errors return 400, conflicts 409 and unknown ids 404. Audit actions are `dns.authoritative.zone.*`, `dns.authoritative.member.*` and `dns.authoritative.record.*`.

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/dns/authoritative` | `{enabled, zones:[zone + {members:[member + {node_name, nameserver, state, report?}], records:[record + {served, healthy}]}]}` |
| POST | `/dns/authoritative/zones` | `{name, hostmaster?, ttl?, negative_ttl?, min_keep?}` |
| PUT / DELETE | `/dns/authoritative/zones/{id}` | Same body as create; DELETE also removes the zone's name servers and records |
| POST | `/dns/authoritative/zones/{id}/members` | `{node_id, listen:[ip], label?, advertise?, port?}` |
| PUT / DELETE | `/dns/authoritative/members/{id}` | Same body as create |
| POST | `/dns/authoritative/zones/{id}/records` | `{name, type: A\|AAAA\|CNAME\|TXT, ttl?, values:[{content, health?:{node_id, rule_id}}]}` |
| PUT / DELETE | `/dns/authoritative/records/{id}` | Same body as create |

Member `state` is `serving`, `updating` (the agent still serves an older version), `error` (a listener failed; see `report.errors`), `waiting` (no report yet, possibly an agent older than 0.137.0) or `offline` (no report for 90 s). Record `served` lists the values answered now; `healthy` has one entry per value: `null` without a health gate, otherwise whether it passes.

Agents receive their answers in the optional `SyncResponse.authoritative_dns` `{digest, listen:[addr], zones:[...]}` on every sync, empty for non-members or while the feature is off. They return `EngineStats.authoritative_dns` `{digest, listening, errors?, queries, nxdomain, refused, truncated, limited}` only to a controller that sent answers. See [DNS.md](DNS.md).

## 0.138.0 WireGuard networking

All routes need a system administrator session (API tokens are refused). Creating or changing networks and members returns 409 while `wireguard` is off; deletions always work. Validation errors return 400, conflicts 409 and unknown ids 404. Audit actions are `wireguard.network.*` and `wireguard.member.*` (create, update, delete, rekey).

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/wireguard` | `{enabled, networks:[network + {interface, relay_in_use?, members:[member + {label, state, error?}], pairs:[{a, b, path, punched?, via?, reason?, retry_in_s?, handshake_age_s?, rx_bytes?, tx_bytes?}]}], nodes:[{id, name, key_reported, problem?}]}` |
| POST | `/wireguard/networks` | `{name, cidr, listen_port?, mtu?}` |
| PUT / DELETE | `/wireguard/networks/{id}` | `{name, cidr?, listen_port?, mtu?, relay?}`; `cidr` cannot change while members exist; DELETE also removes the members |
| POST | `/wireguard/networks/{id}/members` | Node `{kind:"node", node_id, endpoint?, listen_port?, address?}` (409 until the node's agent reported a key) or device `{kind:"device", name, via?, public_key?, address?}`; a device reply adds `config` and, when the panel made the key, `qr_svg`, both shown only once |
| PUT / DELETE | `/wireguard/members/{id}` | Same body; kind, node, address and key cannot change. A node that devices use, or the explicit relay, keeps its endpoint; deleting a node that devices use returns 409 |
| POST | `/wireguard/members/{id}/rekey` | Devices only: a new key pair, returning `config` and `qr_svg` once |

Node member `state` is `up`, `updating` (the agent has not applied the newest state), `error` (see `error`), `waiting` (no report yet, possibly an agent older than 0.138.0) or `offline` (no report for 90 s); devices are `connected` (handshake with the entry node within 180 s) or `idle`. Pair `path` is `direct`, `relayed` (through `via`) or `unreachable`; with NAT traversal (0.139.0) also `probing` (relayed through `via` while trying a direct path). A direct pair of two nodes behind NAT has `punched: true`; a relayed one that tried has `reason` and `retry_in_s` (seconds until the next attempt).

Agents from 0.139.0 add `probes: true` to `EngineStats.wireguard`; only pairs where both agents send it are tried. `GET /agent/watch` (node credential) also returns early with `wireguard_changed: true` once when NAT traversal changed the node's interfaces since its last sync; agents from 0.139.0 sync at once, older agents ignore the field. `PUT /features/nat-traversal` returns 409 while `wireguard` is off, and `PUT /features/wireguard {enabled:false}` returns 409 while `nat-traversal` is on.

Agents receive `SyncResponse.wireguard` and return `EngineStats.wireguard` as described in [WIREGUARD.md](WIREGUARD.md).

## 0.140.0 Cross-panel sharing

Administration routes need a system administrator session (API tokens are refused). Creating, changing, inviting, pausing and resuming return 409 while `federation` is off; revoking and deleting always work. See [FEDERATION.md](FEDERATION.md).

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/federation` | `{enabled, panel_id, grants:[share + {node_name, statement, quota_used_bytes?, applied, ack_mismatch}], remotes:[received share]}`; secrets and secret hashes are never included |
| POST | `/federation/grants` | `{name, node_id, public_host, listen_ip?, port_start, port_end, max_rules, kinds:["forward"\|"shadowsocks"], rate_bytes_per_sec?, upload_bytes_per_sec?, download_bytes_per_sec?, quota_bytes?, expires_at_ms?, allow_sources, allow_destinations?, deny_destinations?, allow_private_destinations?}`; 409 when the ports overlap another rule or share on the node, or with `upload_bytes_per_sec` / `download_bytes_per_sec` (each 1024..=2^40, like `rate_bytes_per_sec`) when the node's agent does not support separate limits |
| PUT / DELETE | `/federation/grants/{id}` | Same body (`node_id` cannot change; `quota_bytes` can change but not be added or removed); DELETE only after revoke |
| POST | `/federation/grants/{id}/invite` | `{owner_url}` (this panel's origin) → `{code, expires_at_ms}`, shown once; 409 once redeemed |
| POST | `/federation/grants/{id}/pause`, `/resume`, `/revoke` | The share; each republishes the node when the share has rules |
| POST | `/federation/remotes` | `{invite, label?}`: redeems the code at the owner and stores the received share. Owner refusals come back as 400, 403 or 409 (a 401 from the owner becomes 409), an unreachable owner as 502 |
| PUT | `/federation/remotes/{id}/rules` | `{expected_revision, rules:[{id?, name, kind, protocol, port, targets?}]}`: the whole rule list, sent to the owner; returns the updated received share |
| POST | `/federation/remotes/{id}/sync` | Pulls the share now and confirms its statement |
| DELETE | `/federation/remotes/{id}` | Forgets the received share on this panel only |

Public routes the receiving panel calls on the owner (`Authorization: Bearer <64-hex secret>` except redeem):

| Method | Path | Body / result |
| --- | --- | --- |
| POST | `/federation/peer/redeem` | `{invite_id, invite_secret, panel_id}` → `{secret, shared}`; 401 for an unknown, wrong or expired invite, 409 once used |
| GET | `/federation/peer/grant` | `shared`: `{grant_id, owner_panel_id, name, public_host, port_start, port_end, max_rules, kinds, rate_bytes_per_sec?, upload_bytes_per_sec?, download_bytes_per_sec?, quota_bytes?, quota_used_bytes?, expires_at_ms?, allow_sources, state, revision, rules:[{id, name, kind, protocol, port, targets?, password?}], applied, statement:{as_of_ms, upload_bytes, download_bytes}}` |
| PUT | `/federation/peer/grant/rules` | `{expected_revision, rules}` → `shared`; 403 when a request is wider than the share, 400 when malformed, 409 when paused, expired or the revision is stale |
| POST | `/federation/peer/grant/ack` | `statement` the receiver saw → `{ok:true}` |

A revoked share or an unknown secret returns 401; all peer routes return 409 while the owner's `federation` switch is off. `PUT /features/federation {enabled:false}` returns 409 while any share is not revoked or any received share is kept.

## Shared rules

One forwarding rule kept on several entry servers ("lines") with the same listen port; see [SHARED_RULES.md](SHARED_RULES.md). Each line holds an ordinary rule on its node, so agents and the rule format are unchanged; the controller keeps only the membership record in metadata (`shared_rule:<id>`). Reads need a session or a token with `read`; every other route needs a writable role and, for tokens, `nodes:write`, like rules. A shared rule belongs to the tenant of its lines; all lines must share one tenant, and other tenants get 404. Audit actions are `shared_rule.create`, `shared_rule.update`, `shared_rule.pause` and `shared_rule.delete`.

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/shared-rules` | `[{id, tenant_id, name, listen_port, created_at_ms, updated_at_ms, drift:[path], members:[{node_id, rule_id, node_name, missing, rule, entry, drift:[path]}]}]` |
| POST | `/shared-rules/precheck` | `{node_ids, listen_port\|null, rule, id?}` → `{listen_port, ok, error, lines:[{node_id, node_name, online, in_range, port_start, port_end, port_free, valid, error}]}`; reserves nothing. `listen_port: null` picks the lowest port inside every line's forwarding range (default 20000–29999) that is free on all of them; `id` (when editing) keeps that shared rule's own lines from counting as taken |
| POST | `/shared-rules` | `{name, node_ids, listen_port, rule}`: 1–32 distinct nodes; one new rule per node, published in one batch |
| POST | `/shared-rules/from-rule` | `{node_id, rule_id, add_node_ids}`: the rule becomes the first line and keeps its id, port and counters; copies go to the added nodes on the same port. 409 when the rule already belongs to a shared rule |
| PUT | `/shared-rules/{id}` | `{name, node_ids, listen_port, rule}`: the full set of lines; sets the common fields on every line, adds and removes lines, and gives every line a new meter epoch when the port changes. An empty `node_ids` is 400 |
| POST | `/shared-rules/{id}/pause` | `{paused}`: sets `enabled` on every line in one batch |
| DELETE | `/shared-rules/{id}` | Deletes every line's rule in one batch and the record; `?keep_rules=true` deletes only the record → `{ok:true}` |

`rule` is a rule object whose common fields apply to every line. `id`, `tenant_id`, `meter_epoch`, `name` and `listen` may be left out: the outer `name` and `listen_port` win, and each line gets its own identity, its node's forwarding listen IP (or `0.0.0.0`) and keeps its own `advertise`. An omitted `owner_id` means the caller. Port ranges (`listen_end_port`) and managed protocol gateways are refused with 400. `port_free` counts every rule on the node whose port or range contains the port, enabled or not, plus gateway ports and the port ranges of cross-panel shares; `in_range` is advice only. `entry` is the node's forwarding host with the port, else the rule's `advertise`, else a specific listen address, else `null`. `drift` lists common-field paths (such as `targets[0].address` or `listen_port`) where a line differs from the first present line; `missing` lines lost their rule or node and are dropped from the record by the next save.

Errors: 400 invalid input, 403 permission, 404 unknown or invisible, 409 conflicts (the port is taken on a line, a revision changed, the rule already belongs to a shared rule). When the cause is on particular lines the body adds `lines: [{node_id, error}]`; nothing is changed on any line.

## Endpoint groups and saved chains

An endpoint group is one layer of alternative servers; a saved chain is an ordered list of 1–6 groups. Building a forwarding from a chain creates ordinary rules: the entry targets every server of layer 1, each server of a layer targets every server of the next layer through `via`, and each server of the last layer targets the destination. See [CHAINS.md](CHAINS.md). Records live in metadata (`endpoint_group:<id>`, `forwarding_chain:<id>`, and `chain_use:<entry rule id>` for each forwarding built), so agents and the rule format are unchanged. Reads need a session or a token with `read`; every other route, including `plan`, needs a writable role and, for tokens, `nodes:write`. A group belongs to the tenant of its servers, a chain to the tenant of its groups; other tenants get 404. Audit actions are `endpoint_group.create|update|delete` and `forwarding_chain.create|update|delete|apply`.

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/endpoint-groups` | `[{id, tenant_id, name, description, members:[{node_id, node_name, missing}], used_by:[{id, name}], created_at_ms, updated_at_ms}]` |
| POST | `/endpoint-groups` | `{name, description?, members:[node_id]}`: 1–32 distinct servers of one tenant, in order; needs write permission on each |
| PUT | `/endpoint-groups/{id}` | Same body with the full member list. 409 when the change would put one server in two layers of a chain that uses the group |
| DELETE | `/endpoint-groups/{id}` | `{ok:true}`; 409 while a chain uses the group |
| GET | `/chains` | `[{id, tenant_id, name, enabled, layers:[{group_id, group_name, balance, members}], uses:[{entry_rule_id, entry_node_id, entry_node_name, name, missing, layers:[[{node_id, rule_id, node_name, missing}]], out_of_date, changes:[{layer, added, removed}]}], created_at_ms, updated_at_ms}]` |
| POST | `/chains` | `{name, enabled?, layers:[{group_id, balance?}]}`: 1–6 layers; a group can be only one layer and a server only in one layer. `enabled` defaults to true, `balance` to `weighted_round_robin` |
| PUT | `/chains/{id}` | Same body with the full layer list; forwardings already built are not changed |
| DELETE | `/chains/{id}` | `{ok:true}`; forgets the chain's uses and keeps every rule built from it |
| POST | `/chains/{id}/plan` | `{entry_node_id, name, protocol, target, entry_port\|null, owner_id?}` → `{entry_rule_id, hops:[{layer, node_id, node_name, rule_id, listen, advertise}], batch:{updates}, preview}`; writes and reserves nothing |
| POST | `/chains/{id}/apply` | Same body plus optional `expected_revisions:{node_id: revision}` from a plan → `{entry_rule_id, hops, published}`; publishes every server in one batch and records the use, or changes nothing |

Each layer's `balance` is how the previous hop chooses among that layer's servers; the last layer reaches `target` with weighted round robin. A `lowest_latency` layer adds a TCP connect health check to the rules that choose it and requires `protocol: tcp`. Endpoints come from the same allocation as `/configurations/allocate-endpoints` (up to 64 servers here); `entry_port` sets the entry's port on its forwarding defaults. Rules are plain TCP/UDP forwarding named `name · 1` (entry), `name · 2` (layer 1) and so on; rule ids are generated again by `apply`. Refused with 400: the entry server inside the chain or in another tenant, more than 64 servers, an invalid target or port, a server without a forwarding address, `lowest_latency` with UDP. Refused with 409: a disabled chain, a deleted group or member server, a taken or exhausted port, and `expected_revisions` that no longer match. When the cause is on particular servers the body adds `lines: [{node_id, error}]`.

`out_of_date` is true when the members of some layer's current group differ from the servers the forwarding was built with (order does not count); `changes` lists them per layer from 1. Nothing re-syncs a forwarding automatically. Deleting a node is not blocked by groups or uses; it then shows as `missing`, and building from a group with a deleted member is 409 until the group is saved without it.

## Reverse tunnels

A public server accepts users on a public port; a private server behind NAT keeps one outbound TLS tunnel connection to it and connects each user to its target (`host:port` as the private server sees it). See [REVERSE_TUNNELS.md](REVERSE_TUNNELS.md). Records live in metadata (`reverse_tunnel:<id>`; the per-tunnel token in `reverse_tunnel_token:<id>`, never returned), so the schema is unchanged. The public end is an ordinary rule `rt-…` on the public server with `reverse_tunnel: <id>`, metered and limited like any rule; publishing may change only its limits (`allow_sources`, `deny_sources`, `rate_bytes_per_sec`, `rate_limits`, `max_connections`, `udp_max_sessions`, `quota_bytes`, `expires_at_ms`, `idle_timeout_secs`, `connect_timeout_ms`, `budget_ids`), other changes to it are 400, and any other rule on a port a tunnel holds is 409. Reads need a session or a token with `read`; writes need a writable role, write permission on both servers and, for tokens, `nodes:write`. Both servers must be different and in one tenant; other tenants get 404. Audit actions are `reverse_tunnel.create|update|delete`, without the token.

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/reverse-tunnels` | `[{id, tenant_id, name, public_node_id, private_node_id, public_port, listen_ip, protocol, target, tunnel_port, enabled, created_at_ms, updated_at_ms, public_node_name, private_node_name, public_missing, private_missing, state, reason, connected_since_ms, connected_for_secs, entry, rule_id, upload_bytes, download_bytes}]`; `state` is `waiting`, `connected`, `error` or `disabled`, with `reason` for the first and third |
| POST | `/reverse-tunnels` | `{name, public_node_id, private_node_id, public_port, listen_ip?, protocol: tcp\|udp\|tcp_udp, target, tunnel_port?, enabled?}` → the tunnel as listed; `tunnel_port` defaults to 29123 and is shared by every tunnel of a public server, `enabled` defaults to true |
| PUT | `/reverse-tunnels/{id}` | Same body; an omitted `enabled` keeps the switch. Changing either server makes a new token; a new public port or public server starts a new meter period |
| DELETE | `/reverse-tunnels/{id}` | `{ok:true}`; removes the public end's rule |

Errors: 400 invalid input (name 1–120 bytes, the same server twice, servers of two tenants, port 0 or equal public and tunnel ports, a target that is not `host:port`, a multicast listen IP, unknown fields or a body that does not parse), 403 permission, 404 unknown or invisible, 409 a taken port (a rule, its port range or gateway port, a cross-panel share, another tunnel's public port, or another tunnel using the public port as its tunnel port) or a paused or expired server. Creating a tunnel never waits for the agents: until both have reported the capability and the public server its key fingerprint, the tunnel is `waiting` with the reason, and nothing is sent to either agent. Deleting a server is not blocked; its tunnels show it as missing (`public_missing` / `private_missing`).

Agents receive `SyncResponse.reverse_tunnels` and return `EngineStats.reverse_tunnel` (only to a controller that sent the field) as described in [REVERSE_TUNNELS.md](REVERSE_TUNNELS.md#同步协议). `GET /agent/watch` also returns early with `reverse_tunnels_changed: true` once after a node's tunnels changed; newer agents sync at once, older agents ignore the field.

## Upload, download and burst speed limits

Separate upload and download limits at the rule, server and user-total levels, and burst limits at the rule and server levels; see [RATE_LIMITS.md](RATE_LIMITS.md). Upload is what a hop's client sends toward its target, download what comes back (the same for UDP). Every limit that is set applies at once, and `rate_bytes_per_sec` keeps its meaning (upload and download combined). New fields are left out while unset, so existing configurations, backups and API calls are unchanged.

**`rate_limits`** on a rule (`Rule.rate_limits`) and on a node configuration (`NodeConfig.rate_limits`, `PUT /nodes/{id}/config`, `/configurations/preview|publish` updates):

| Field | Meaning |
| --- | --- |
| `upload_bytes_per_sec?` | Upload limit, 1..=10^12 bytes/second |
| `download_bytes_per_sec?` | Download limit, 1..=10^12 bytes/second |
| `burst?` | `{bytes_per_sec, secs}`: burst of the combined `rate_bytes_per_sec` |
| `upload_burst?`, `download_burst?` | Burst of the upload or download limit |

A burst needs its limit S, a burst rate B with S < B ≤ 10^12 bytes/second and a burst time W of 1..=86400 seconds; otherwise 400. Its credit holds (B − S) × W bytes and starts full; sending above S spends it at (rate − S), sending below S earns it back at (S − rate) up to that capacity, and without credit the limit is S. An empty object is the same as none and is left out. On a publish, an omitted node `rate_limits` keeps the node's limits and `null` clears them; rules carry theirs in the rule. Rollback restores both.

**User totals:** `PUT /users/{id}/rate` takes `upload_bytes_per_sec` and `download_bytes_per_sec` (1024..=2^40; omitted keeps, `null` clears) next to `rate_bytes_per_sec`; each total is split between the user's servers like the combined one, so the shares in force per direction never add up to more than its total once every server has synced. There is no user-level burst. `GET /users/{id}/rate` returns `upload_nodes` and `download_nodes` next to `nodes`.

**Cross-panel shares:** `upload_bytes_per_sec` and `download_bytes_per_sec` on a share work like its `rate_bytes_per_sec`: they limit each of the share's rules and the share's account across them, and the receiving panel sees them in `shared`. A receiving panel's publish that changes a shared rule's limits is 400, as for its other fields.

**Agents and old agents.** Every sync response carries `rate_limits: true`; an agent of this release then returns `EngineStats.rate_limits: {bursts?:[{rule_id?, direction: combined|upload|download, credit_bytes, capacity_bytes}]}` (`rule_id` left out for the node's own limits), and the controller records `rate_limit_node:<node id>` the first time. `GET /nodes` shows it as `rate_limit_support` and the burst credit in `stats.rate_limits`. User shares (`SyncResponse.user_rates[]`) keep their format for a combined total and add `upload` / `download` (`{rate_bytes_per_sec, fallback_bytes_per_sec}`) only for a node that reported support; agent reports (`EngineStats.user_rates[]`) add `upload` / `download` (`{bytes, waited_ms, enforced_bytes_per_sec}`) only for those shares. Older agents ignore the unknown sync field, never report support, and reject a configuration or share with the new fields, so the controller refuses instead:

| Status | When | `error` |
| --- | --- | --- |
| 409 | A publish (any route: single, batch, rollback, template, shared rule, chain, reverse tunnel, cross-panel share) gives a server whose agent has not reported support a rule or node `rate_limits` | `the agent on server <name> is too old for separate upload/download or burst speed limits; upgrade it first`, or for a server that never connected `server <name> has not connected to the panel yet; separate upload/download or burst speed limits need its agent to report in first` |
| 409 | A publish gives such a server an enabled rule of a user with an upload or download total | `user <username> has separate upload/download speed limits: <one of the reasons above>` |
| 409 | `PUT /users/{id}/rate` adds an upload or download total while a server carrying the user's enabled rules lacks support; a share with upload or download bandwidth on such a server | One of the server reasons above |
| 400 | Invalid limits or bursts | The validation message |

The panel shows these reasons in its language. Metering, quotas, shared budgets and the usage ledger are unchanged.

## Speed tests

Built-in speed tests; see [SPEED_TESTS.md](SPEED_TESTS.md). A **server test** measures one server against Cloudflare's fixed speed endpoints (`https://speed.cloudflare.com/__down?bytes=N` and `POST /__up`; no other URL can be given) or two servers against each other: the receiving (peer) server listens on a temporary test port, and the testing server connects to the peer's forwarding host (through its public-port mapping) with a per-test random token. A **path test** runs the server-to-server test on each segment of a rule's effective path (entry → next hop → … → last hop, following each hop's preferred target and its `via`), dialing the host that hop's target uses, and then times one TCP connect from the last hop to the rule's target. Test traffic never passes through a rule: no speed limit applies, and nothing is metered or counted against quotas, budgets, plans or the usage ledger (`metered` is always `false`). Jobs live in metadata (`speed_test:<id>`; tokens apart in `speed_test_token:<id>`, deleted when the job ends and never returned), so the schema is unchanged; the last 50 ended jobs are kept. Audit actions are `speed_test.start|cancel|finish`, without tokens.

Reads need a session or a token with `read`; starting and cancelling need a token with `nodes:write`. Server tests are for system administrators only. Path tests are for system administrators and users with write permission on every server of the path; other tenants get 404. A non-administrator sees only the path tests of their tenant.

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/speed-tests` | `[job]`, running jobs first, then newest first |
| POST | `/speed-tests` | `{mode: cloudflare\|server, node_id, peer_node_id?, port?, direction: upload\|download\|both, duration_secs?, bytes?, streams?}` → `job`. `node_id` is the testing server (it dials, or talks to Cloudflare); `peer_node_id` the receiving server of a `server` test; `port` its test port (1024–65535), omitted picks the highest free port of the peer's forwarding range |
| GET | `/speed-tests/path?node_id=&rule_id=` | The plan: `{node_id, rule_id, rule_name, hops:[{node_id, node_name, rule_id, rule_name}], segments:[{from_node_id, from_name, to_node_id, to_name, rule_id, target_address}], target?:{node_id, node_name, rule_id, address}, limits:[limit], reason?, metered:false}`; `reason` says why it cannot start now (the refusals below), or is null |
| POST | `/speed-tests/path` | `{node_id, rule_id, direction, duration_secs?, bytes?, streams?}` → `job` |
| GET | `/speed-tests/{id}` | `job` |
| DELETE | `/speed-tests/{id}` | `job` with `state: cancelled`; the agents at both ends stop at once |

**Parameters:** `direction` `both` runs upload, then download. `duration_secs` is 5–60 seconds per direction, `bytes` 1,000,000–1,000,000,000 bytes per direction (split between the streams, still at most 60 seconds); give one or neither (then 10 seconds). `streams` is 1–8, default 4. About 2 seconds of warm-up per direction are not part of the result. Upload is from the testing server (on a path, from the entry towards the last hop), download towards it. Unknown fields (for example a `url`) and bodies that do not parse are 400 `invalid speed test: …`.

**`job`:** `{id, kind: server|path, mode: cloudflare|server, tenant_id, started_by, started_by_name, params:{direction, duration_secs?, bytes?, streams}, port?, rule?:{node_id, rule_id, name}, node_ids, segments:[segment], target?, limits?:[limit], state: running|finished|failed|cancelled, step, step_started_ms, created_at_ms, finished_at_ms?, error?, progress, slowest_segment, metered:false}`.

- `segment`: `{from_node_id, from_name, to_node_id?, to_name?, rule_id?, listen?, address, state: pending|running|finished|failed|cancelled, results?:[result], rejected_connections?, error?, started_at_ms?, finished_at_ms?}`. `listen` is where the receiving server listened; `address` what the testing server dialed, or `speed.cloudflare.com`. `rejected_connections` counts connections the listener closed for a wrong token or format.
- `result` (one per direction): `{direction, bytes, measured_ms, average_bps, peak_bps, streams, failed_streams?, errors?, limited?}`. Bits per second; `bytes` and `measured_ms` cover the measured window after the warm-up; `peak_bps` is the most bits in any one second of it. `limited` is true when the speed service refused further requests (HTTP 429) after part of the direction; the result then covers only what came before.
- `target` (path tests whose last hop has a fixed TCP target): `{node_id, node_name, rule_id, address, state, connect_us?, error?}`; connect only, no data.
- `limit`: `{kind: rule|server, node_id, node_name, rule_id?, rule_name?, rate_bytes_per_sec, rate_limits?, quota_bytes?}`: the limits configured along the path, shown for comparison only; none of them applied to the test.
- `progress` (while a segment runs): `{segment, direction, elapsed_ms, bytes, current_bps}`; `slowest_segment` (path tests) is the index of the segment whose slower direction has the lowest average.

A job runs its segments one after another, then the target probe. A step that has no result by its deadline (the task's hard limit plus 30 seconds; 45 seconds for the probe) fails with `no result from server <name> in time` and the job goes on. A job is `finished` when at least one step was measured, otherwise `failed`.

| Status | When | `error` |
| --- | --- | --- |
| 400 | Parameters out of range, both `duration_secs` and `bytes`, a test port below 1024, a Cloudflare test with `peer_node_id` or `port`, a server test without a peer or with the same server twice | The validation message |
| 403 | A server test by a non-administrator; a path test or cancel by a read-only role or without write permission on a server of the path; a token without `nodes:write` | `server speed tests need system administrator access`, `read-only role cannot run speed tests`, `read-only role cannot stop speed tests` |
| 404 | Unknown or invisible server, rule or job | |
| 409 | A server of the test is in another running test | `server <name> is already running a speed test` |
| 409 | A server's agent has not reported speed-test support | `the agent on server <name> is too old for speed tests; upgrade it first`, or `server <name> has not connected to the panel yet; speed tests need its agent to report in first` |
| 409 | A server has not synced for 90 seconds | `server <name> is offline` |
| 409 | A server-to-server test or segment where either server has no forwarding host | `server <name> has no forwarding host; set the forwarding address and port range in its settings first` |
| 409 | No free port, or the requested port is taken by a rule (port range, gateway port), reverse tunnel, shared rule or cross-panel share | `server <name> has no free port in its forwarding port range for a speed test`, `port <port> on server <name> is used by a rule, reverse tunnel or share; choose another port` |
| 409 | A rule with no path to test | `this rule is a proxy service or protocol gateway with no fixed target; there is no path to test`, `this rule is the public end of a reverse tunnel and reaches its target through the tunnel; test the two servers with a server speed test instead`, `this rule is shared from another panel (cross-panel sharing); its path cannot be tested here`, `this rule runs on one server and has no TCP target whose connect time could be measured`, `the next hop of rule <rule> on server <name> no longer exists`, `the path is too long or loops` |
| 409 | Cancelling a job that has ended | `this speed test has already ended` |
| 429 | A non-administrator starting a test within 1 minute of their last one | `wait <n> s before starting another speed test` |

**Agents and old agents.** Every sync response carries `speed_test: true`. An agent of this release then returns `EngineStats.speed_test: {tasks?:[{id, state: running|finished|failed, phase?, elapsed_ms?, bytes?, current_bps?, results?, connect_us?, rejected?, error?}]}` (at most 8 tasks, 2 results each, 4 errors per result; larger reports make the sync 400), and the controller records `speed_test_node:<node id>` the first time; `GET /nodes` shows it as `speed_test_support`. Only such agents receive `SyncResponse.speed_test_tasks` (left out when empty): `[{id, role: listen|dial|cloudflare|connect, params, listen?, address?, token?}]`; an agent stops any task the controller no longer sends. `GET /agent/watch` returns early with `speed_tests_changed: true` once when a node's tasks change, so newer agents sync at once; older agents ignore the field. Agents of 0.147.0 and earlier ignore the new sync fields, never report support and receive nothing; an agent of this release talking to a 0.147.0 controller (which sends no `speed_test`) reports nothing. The panel shows the reasons above in its language.

## Connections and blocked connections

A rule's live connections, its counters and the block records of refused connections; see [CONNECTIONS.md](CONNECTIONS.md). Sessions are fetched from the agent when the panel asks and never stored; block records are kept in the controller's memory only (the latest 1000 per node) and are lost when it restarts, like live logs. **Client addresses and source IPs are personal data.**

Anyone who may read the node's configuration may read both: system administrators everything, other users only rules of tenants they can see (an invisible node or rule is 404; a node's records list only visible rules). Viewers included. API tokens need `read` (a token with only `nodes:write` gets 403).

| Method | Path | Result |
| --- | --- | --- |
| GET | `/nodes/{id}/rules/{rule}/connections` | `{state, taken_at_ms?, totals:{tcp, udp}, sessions:[session], truncated, counters}` |
| GET | `/nodes/{id}/blocks?rule_id=&limit=` | `{supported, blocks:[block]}`, latest change first. `rule_id` (optional) keeps one rule's records; `limit` is clamped to 1–1000, default 200 |

**`state`:** `ready` (a snapshot taken within the last 2 seconds), `pending` (the agent has been asked and has not answered yet; an older snapshot, if any, is still returned with its `taken_at_ms`), `no_answer` (no answer within 30 seconds; reported once, the next request asks again), `unsupported` (the agent never reported support: upgrade it), `offline` (the node has never synced or not within 90 seconds). A request when no snapshot younger than 2 seconds exists asks the agent and wakes it through `GET /agent/watch`; requests within those 2 seconds reuse the snapshot, so polling cannot make the agent take snapshots faster. At most 8 rules of one node wait for an answer at a time; a request for a ninth is 429 `too many connection snapshots are waiting for this server; try again in a few seconds`.

- `session`: `{id, protocol, udp?, client, started_ms, target_index?, target?, remote?, via?:{node_id, rule_id}, destination?, upload_bytes, download_bytes}`. `protocol` is one of `tcp`, `tls`, `websocket`, `wss`, `socks5`, `socks5_udp`, `http_connect`, `http2_connect`, `shadowsocks`, `shadowsocks_uot`, `multipath`, `gateway`, `udp`, `shadowsocks_udp`. `client` is the address the rule sees (after a PROXY header); `target` the configured target, `remote` the address actually connected; `destination` what a proxy client asked for (for HTTP/2 CONNECT, the latest stream's). Bytes are counted where metering counts them; upload is client → target. At most 200 sessions, newest first; `totals` counts all open TCP sessions and UDP sessions of the rule, and `truncated` is true when some are left out.
- `counters`: `{inbound?, targets:[{target_index, target_address, via?, counts}], refused:[{reason, count}]}`, all since the agent started. `inbound` and `counts` have the shape of the hourly connection records (`{attempts, connected, timeout, refused, dns, closed, other, connect_us}`); `inbound` counts the accepted TCP connections (those not refused by the connection limit or source checks) and their inbound setup (PROXY header, TLS, WebSocket), and is absent before the first; `targets` is the per-target (next-hop) distribution. `refused` comes from the latest snapshot and is empty before the first.
- `block`: `{rule_id, protocol, source, reason, detail, first_ms, last_ms, count}`. `source` is an IP address without port. `reason` is one of `source_not_allowed`, `source_denied`, `proxy_untrusted`, `expired`, `connection_limit`, `udp_session_limit`, `http2_stream_limit`, `quota`, `budget`, `inactive`, `no_target`, `destination_denied`, `auth_failed`, `handshake_failed`, `firewall` (a firewall rule set refused it; see [FIREWALL.md](FIREWALL.md)). `detail` is at most 120 characters and never holds credentials or payload. Refusals of the same rule, source IP and reason within 60 seconds of the record's first one are one record with a `count`.
- `supported` is false while the node's agent has not reported support; `GET /nodes` shows the same as `connections_support`.

| Status | When |
| --- | --- |
| 400 | `/blocks` with an unknown query parameter or a `limit` that is not a number |
| 403 | A token without `read` |
| 404 | Unknown or invisible node or rule, including an empty `rule_id` |
| 429 | Eight rules of the node are already waiting for a snapshot |

**Agents and old agents.** Every sync response carries `live_connections: true` (omitted when false). An agent of this release then adds `EngineStats.live_connections: {snapshots?:[{rule_id, taken_at_ms, tcp, udp, sessions?, refused?}], blocks?:{stream, entries:[{id, seq, rule_id, protocol, source, reason, detail?, first_ms, last_ms, count}]}}` to its stats; the controller takes it out before keeping the stats and records `connections_node:<node id>` the first time. Only such agents receive `SyncResponse.live_connection_requests` (rule ids, omitted when empty; the agent answers them in its next sync, at once) and `SyncResponse.block_cursor: {stream, seq}` (the last record the controller holds; the agent sends the records changed after it, at most 200 per sync; a record that changes is sent again with a higher `seq` and replaces the controller's copy, so nothing is counted twice; an unknown `stream` asks for everything the agent still keeps). `GET /agent/watch` returns early with `connections_requested: true` once when the panel asks for a node's sessions. Reports are bounded: at most 4 snapshots, 200 sessions each, addresses of at most 300 bytes, 200 records per sync and details of at most 120 characters; a larger report makes the sync 400. Agents of 0.147.0 and earlier ignore the new fields, never report support and receive nothing; an agent of this release talking to a 0.147.0 controller (which sends no `live_connections`) reports nothing, because that controller's `EngineStats` rejects unknown fields.

## Egress proxies

A rule whose clients choose the destination (an `inbound_socks5`, `inbound_http_connect`, `inbound_http2_connect` or `inbound_shadowsocks` rule) can reach those destinations through an upstream SOCKS5 proxy instead of directly; see [EGRESS_PROXY.md](EGRESS_PROXY.md). The field is left out while unset, so existing configurations, backups and API calls are unchanged.

| Field | Meaning |
| --- | --- |
| `Rule.egress_proxy?` | `{kind: "socks5", servers: [..], username?, password?}`, unknown fields refused. Accepted by `PUT /nodes/{id}/config`, `/configurations/preview\|publish`, rollback, templates, shared rules and chains like any rule field |
| `egress_proxy.servers` | 1..=8 `host:port`, `IPv4:port` or `[IPv6]:port`, tried in order; a server that failed in the last 10 seconds is tried after the others; no duplicates (case-insensitive) |
| `egress_proxy.username`, `egress_proxy.password` | RFC 1929 credentials of the upstream, 1..=255 bytes each without control characters, both or neither; shared by every server and separate from the inbound's credentials. Stored and returned with the rule like a Shadowsocks password; never in audit details, errors, logs or agent reports |
| `Node.egress_proxy_support` | `GET /nodes`: the node's agent reported that it supports egress proxies (metadata `egress_proxy_node:<node id>`) |
| `SyncResponse.egress_proxy` | `true` from controllers of this release (omitted when false) |
| `EngineStats.egress_proxy?` | `{}`, sent by agents of this release only to a controller that sent `SyncResponse.egress_proxy` |

The rule's destination ACL and the inbound's `allow_private_destinations` apply to the client's destination before the upstream is used. A name goes to the upstream unresolved (SOCKS5 address type 3) only when the inbound allows private destinations and the ACL can decide by name and port alone; otherwise the node resolves it, filters the addresses and sends the permitted IP addresses. `outbound_bind` applies to the connection to the upstream; the session's `remote` in `/nodes/{id}/rules/{rule}/connections` is the upstream address. Upstream connection, authentication and SOCKS5 reply failures count as failed destination connections. TCP only: no UDP is sent around the upstream.

| Status | When | `error` |
| --- | --- | --- |
| 400 | `egress_proxy` on a rule without a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks inbound | `an egress proxy applies only to rules whose clients choose the destination: a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks inbound` |
| 400 | The rule's `protocol` is not `tcp`, or its Shadowsocks inbound has `udp_over_tcp` | `an egress proxy carries TCP only; set the rule's protocol to TCP (UDP is never sent around the egress proxy)`, or `an egress proxy carries TCP only; turn off Shadowsocks UDP over TCP` |
| 400 | Invalid servers or credentials | The validation message, e.g. `an egress proxy needs 1..8 servers`, `the egress proxy username and password must be set together`; never the password |
| 400 | A publish sets `egress_proxy` on a cross-panel share's rule | `rule <name> belongs to share <share>; a share's rules cannot have an egress proxy` |
| 409 | A publish (any route: single, batch, rollback, template, shared rule, chain) gives `egress_proxy` to a server whose agent has not reported support | `the agent on server <name> is too old for egress proxies; upgrade it first`, or for a server that never connected `server <name> has not connected to the panel yet; egress proxies need its agent to report in first` |

**Agents and old agents.** Agents of 0.148.0 and earlier ignore `SyncResponse.egress_proxy`, never report support and would reject a rule with the field, so the controller refuses it with the 409 above; configurations without the field reach them unchanged. An agent of this release talking to a 0.148.0 controller (which sends no `egress_proxy`) reports nothing, because that controller's `EngineStats` rejects unknown fields. The panel shows these reasons in its language.

## Firewall rule sets

Named, ordered allow/deny rule lists kept by the controller and bound to a server's inbound or outbound side or to one rule's inbound side; see [FIREWALL.md](FIREWALL.md). The first rule in list order that matches decides, else the set's `default_action`; every bound layer and the rule's own lists must allow. Configurations without bindings are unchanged.

| Method | Path | Body / result |
| --- | --- | --- |
| GET | `/firewall/sets` | `[set]` visible to the caller, by name |
| POST | `/firewall/sets` | `{name, direction, default_action, rules, scope?, tenant_id?}` → `set` |
| GET | `/firewall/sets/{id}` | `set` |
| PUT | `/firewall/sets/{id}` | `{name, direction, default_action, rules, expected_revision?}` → `set`; servers using it are woken, nothing is published |
| DELETE | `/firewall/sets/{id}` | `{ok: true}`; 409 while bound |
| GET | `/nodes/{id}/firewall` | `status` |
| PUT | `/nodes/{id}/firewall` | `{inbound_set_id: id\|null, outbound_set_id: id\|null}` → `status` (system administrators) |
| POST | `/firewall/test` | `{set_id}` or `{node_id, rule_id?}`, with `{source}` (inbound) or `{destination, port, address?}` (outbound) → `test result` |

| Field | Meaning |
| --- | --- |
| `set` | `{id, scope: "system"\|"tenant", tenant_id\|null, name, direction: "inbound"\|"outbound", default_action: "allow"\|"deny", rules, revision, created_at_ms, updated_at_ms, bindings: [{layer, node_id, node_name, rule_id?, rule_name?}]}`. `name` 1–120 characters without surrounding spaces or control characters; `scope` (default `tenant`) and `tenant_id` (default the caller's) are set at creation only; `direction` never changes |
| `rules[]` | `{action: "allow"\|"deny", match: {sources?, destinations?, ports?}}`, 0–256 per set, unknown fields refused. Inbound: `sources` only, 1–256 IPv4/IPv6 networks (`/32` or `/128` for one address). Outbound: `destinations` (IP, CIDR, exact domain or `*.suffix`, which matches subdomains only) and/or `ports` (`443`, `8000-8080`), at most 256 each, at least one of them; `*` is refused (use the default action) |
| `Rule.firewall_inbound_set?` | The id of a tenant inbound set of the rule's own tenant; checked after the server's inbound set and before `allow_sources`/`deny_sources`. Accepted by `PUT /nodes/{id}/config`, `/configurations/preview\|publish`, rollback, templates, shared rules and chains like any rule field; omitted when unset |
| `status` (`Node.firewall` in `GET /nodes`) | `{inbound_set_id, inbound_set_name, outbound_set_id, outbound_set_name, rule_bindings, desired_hash, applied_hash, error, state}`; `state` is `applied` (the agent confirmed `desired_hash`), `waiting`, `offline` (no sync for 30 seconds), `too_old` (never reported support), `not_connected` or `unused` (nothing bound and no support). A sync without `EngineStats.firewall` (a downgraded agent, or a new agent's first sync) clears `applied_hash` |
| `Node.firewall_support` | `GET /nodes`: the node's agent reported that it enforces rule sets (metadata `firewall_node:<node id>`) |
| `test result` | `{direction, decision: "allow"\|"deny"\|"needs_address", layers: [{layer, set_id?, set_name?, rule_index?, default_action, result, detail?}], policy_hash?}`. `layer` is `set` (a set alone), `server_inbound`, `rule_inbound`, `server_outbound` or `rule_lists` (the rule's own lists, with `rule_id`); `rule_index` is 0-based; `result` is `allow`, `deny`, `needs_address` (a name whose addresses decide: give `address`) or `missing` (the bound set is unusable: refuses). A binding is answered with the server's desired policy, whose hash is `policy_hash`. For anyone but a system administrator, a layer whose set the caller cannot see (a system set) keeps its `result` but has no `set_id`, `set_name` or `rule_index`, `default_action: false` and `detail: "a rule set outside your tenant decides"` |
| `SyncResponse.firewall` | `{hash, policy?}`: the server's policy (`{server_inbound?, server_outbound?, sets?: [{id, name, direction, default_action, rules}]}`: the bound set ids and every set the server or its rules use) and its SHA-256 (sets ordered by id); `policy` is left out when the agent's last report has that hash. Sent as an opaque value, so an agent that cannot read it keeps syncing and reports why |
| `EngineStats.firewall?` | `{applied_hash, error?}`, sent by agents of this release only to a controller that sent `SyncResponse.firewall`. `error` (at most 512 characters from the agent; the controller takes up to 2048 bytes) says why the last policy was not applied, or else which sets of the policy in force could not be used and refuse everything |
| `GET /agent/watch` | Returns early with `firewall_changed: true` when a set the server uses or its bindings change |

| Status | When | Message |
| --- | --- | --- |
| 400 | Invalid name, too many rules or entries, a match of the wrong direction, a bad destination or port | The validation message, e.g. `rule 1: an inbound set matches source addresses only, not destinations or ports` |
| 400 | A changed `direction`, `scope` or `tenant_id` | `the direction of a rule set cannot change`, `the scope and tenant of a rule set cannot change` |
| 400 | A rule bound to an outbound set; a protocol gateway rule bound to any set; a share's rule bound to a set | `rule <name>: rule set <set> is an outbound set; a rule takes an inbound set`, `rule <name>: a protocol gateway checks its clients in the protocol engine and cannot take a firewall rule set`, `rule <name> belongs to share <share>; a share's rules cannot have a firewall rule set` |
| 400 | A server bound to a tenant set or a set of the other direction | `rule set <set> belongs to a tenant; servers take system rule sets`, `rule set <set> is an <direction> set; bind it as the server's <direction> set` |
| 400 | A server's policy over 1 MiB | `the rule sets used on server <name> exceed 1024 KiB together; use fewer or smaller sets` |
| 400 | `POST` or `PUT` of a set over 1 MiB serialized | `a rule set is at most 1024 KiB; use fewer rules or entries` |
| 400 | A tester question without a source or destination, or both | `give a source address (inbound) or a destination and port (outbound)`, `an outbound test needs a destination port (1-65535)`, `give either set_id or node_id` |
| 403 | A read-only role or a token without `nodes:write` changing sets; anyone but a system administrator binding servers or keeping system sets; a token without `read` reading or testing | `only system administrators bind rule sets to servers`, `only system administrators keep system rule sets` |
| 404 | A set of another tenant, a system set for a tenant user, an unknown set, or a rule bound to a set that is not its tenant's | `firewall rule set not found`, `firewall rule set <id> not found` |
| 409 | `PUT` with a stale `expected_revision` | `the rule set changed; reload before saving` |
| 409 | `POST` when the tenant keeps 64 sets, or there are 64 system sets | `at most 64 firewall rule sets per tenant; delete one first`, `at most 64 system firewall rule sets; delete one first` |
| 409 | `DELETE` of a set still bound | `rule set <name> is still bound: server <name> (inbound), rule <rule> on server <name>; remove these bindings first` |
| 409 | A new server binding, or a publish (any route) giving `firewall_inbound_set` to a rule, on a server whose agent has not reported support | `the agent on server <name> is too old for firewall rule sets; upgrade it first`, or for a server that never connected `server <name> has not connected to the panel yet; firewall rule sets need its agent to report in first` |

**Agents and old agents.** Agents of 0.149.0 and earlier ignore `SyncResponse.firewall`, never report support and would reject a rule with `firewall_inbound_set`, so the controller refuses bindings with the 409 above; configurations without bindings reach them unchanged, and removing a binding is always allowed. An agent of this release talking to a 0.149.0 controller (which sends no `firewall`) reports nothing, because that controller's `EngineStats` rejects unknown fields, and drops any policy it kept. The panel shows these reasons in its language.
