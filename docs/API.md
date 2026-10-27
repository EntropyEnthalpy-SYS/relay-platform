# 开发版 API 契约

基础路径 `/api/v1`，JSON。用户与节点分别使用独立的 256-bit 随机 Bearer 凭据；持久化存储只保存服务端令牌哈希。用户会话八小时过期。Agent 的长期凭据保存在自己的私有状态库。所有跨机器请求须通过 HTTPS。

API 尚处开发阶段；以 `model.rs`、`lease.rs` 等公开模型的严格字段定义为准。未识别字段返回错误，不能假装启用尚未实现的功能。单次请求限制 2 MiB。

| 方法 | 路径 | 请求或用途 |
| --- | --- | --- |
| POST | `/auth/login` | `{username,password}` → `{token,user,expires_in_seconds}` |
| GET | `/session` | 当前用户与角色 |
| POST | `/auth/logout` | 撤销当前会话 |
| GET / POST | `/nodes` | 按可选 q/kind/group/tag/lifecycle 筛选可见节点；`{name,tenant_id?,lease_policy?,settings?}` 创建节点并返回一次性注册令牌；省略或 `null` 的 `lease_policy` 为离线（可用优先）模式，`{}` 或 `{ttl_ms}` 为严格租约 |
| PUT | `/nodes/{id}/profile` | `{expected_revision,name,settings}`；更新完整资料，独立于转发修订 |
| POST | `/nodes/profiles` | `{updates:[{node_id,update}]}`；原子保存 1..100 个节点资料，逐节点返回修订 |
| GET | `/nodes/{id}/config` | 当前期望配置，包含修订号和规则 |
| PUT | `/nodes/{id}/config` | `{expected_revision,rules,rate_bytes_per_sec?}`；并发冲突返回 409，成功生成下一版本。省略 `rate_bytes_per_sec` 保留节点总限速，`null` 取消 |
| GET | `/nodes/{id}/credential` | 可见节点的身份阶段/版本、轮换/撤销/替换回执与受保护配额周期；不返回秘密或哈希 |
| POST | `/nodes/{id}/credential/rotate` | `{expected_revision}` 请求 Agent 自行生成并轮换凭据；权限与版本检查 |
| POST | `/nodes/{id}/credential/revoke` | `{operation_id,expected_revision,reason}`；退役身份、保留旧窗口与未知预留 |
| POST | `/nodes/{id}/credential/replace` | `{operation_id,expected_revision,enrollment_token,valid_for_seconds,offline_stop_attested?,lease_policy?}`；签发或重签限时替换令牌 |
| GET | `/nodes/{id}/health` | 实际修订对应的目标健康、年龄、候选原因、探测流量与容量；按节点权限过滤 |
| GET | `/nodes/{id}/history` | 最近 100 次配置修订 |
| POST | `/nodes/{id}/rollback` | `{revision,expected_revision}`；把历史规则作为新修订发布，账本不回滚 |
| POST | `/nodes/{id}/drain` | `{draining}`；把所有 `via` 指向该节点的上游目标设为（或取消）维护排空，在一个批次中发布有变化的上游节点；没有上游指向它时返回 409，已是目标状态时返回空结果 |
| GET | `/topology` | 当前可见节点、配置、声明边、根规则及应用状态 |
| POST | `/configurations/preview` | `{updates:[{node_id,expected_revision,rules}]}`；只读校验并返回候选配置及完整差异，需要写权限 |
| POST | `/configurations/publish` | 同预览请求；1..64 个节点的期望配置在同一事务中提交 |
| GET / POST | `/users` | 列出用户；`{username,password,role,tenant_id?}` 创建用户 |
| POST | `/users/{id}/revoke-sessions` | 撤销该用户全部现有 Web 会话 |
| GET / PUT | `/users/{id}/rate` | 跨节点用户总限速。PUT `{rate_bytes_per_sec}`（1024..=2^40，`null` 取消）仅系统管理员；GET 按租户可见，返回总速率和各节点当前份额、实测速率、是否用满、距上次同步毫秒数 |
| POST | `/tenants` | `{name}`；仅系统管理员 |
| GET | `/usage` | 最近 2,000 条已上报的规则/周期累计记录，不是全库聚合接口 |
| GET / POST | `/budgets` | 返回 `{allocation_paused,budgets}`；创建 `{scope,scope_id,name,limit_bytes,quantum_bytes}` |
| GET | `/budgets/{id}/reservations` | 按所属租户只读分页查看开放预留；可选 `after` 游标，每页最多 100 条 |
| PUT | `/budgets/{id}` | `{expected_revision,limit_bytes,quantum_bytes}`；修改额度，不清零用量 |
| GET | `/audit` | 最近 200 条全局审计；仅系统管理员 |
| GET | `/recovery` | `{enabled,healthy,head}`；仅系统管理员，读取控制器恢复日志状态 |
| GET | `/control/metrics` | 仅系统管理员；返回本次控制器运行的节点同步统计 |
| GET | `/metrics` | 认证的 Prometheus 文本：构建信息、恢复日志、节点在线、应用/期望修订、配置同步、最后同步、活动 TCP/UDP、接纳/拒绝/失败/丢弃/预热计数、转发字节、应用错误、系统资源、计量/额度恢复、目标健康，以及多路径会话/路径/负载/失败计数 |
| GET | `/telemetry` | 可见节点最近 24 小时的逐次回报采样和事件，供总览页使用；见下文“0.19.0 遥测” |
| GET | `/alerts` | 仅系统管理员；告警设置、通道（不含地址和密钥）、当前与最近恢复的告警、发送记录；见下文“0.19.0 告警通知” |
| PUT | `/alerts/settings` | `{maintenance_until_ms}`；仅系统管理员，登录会话 |
| POST | `/alerts/channels` | `{name,enabled,min_severity,target}`；仅系统管理员，登录会话 |
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

规则新增可选 `health_check`，逐目标新增 `priority`（缺省 0，越小越优先）和 `max_sessions`（缺省不设单目标上限）。健康检查必须覆盖规则的实际 TCP/UDP 协议；请求/预期内容使用有界 Base64。状态机、恢复等待、端口映射、目标容量作用域、实际出口和探测计量见 [HEALTH.md](HEALTH.md)。

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
| POST | `/subscriptions` | `{name,format,template,expires_in_days,user_id?}` → `{subscription,token}`；令牌只返回一次 |
| GET | `/subscriptions/{id}` | 订阅元数据 |
| GET | `/subscriptions/{id}/preview` | `{content,content_type,entries,skipped}`；普通 TCP/TLS/WS 规则明确列入 `skipped` |
| POST | `/subscriptions/{id}/rotate` | 新令牌，旧令牌立即失效 |
| DELETE | `/subscriptions/{id}` | 删除记录与索引 |
| GET | `/sub/{token}` | 公开端点，无登录；60 次/分钟/令牌；`Cache-Control: no-store` |

`format` 为 `v2ray`、`clash`、`surge`、`shadowrocket`。`template` 为 `{name_prefix,host,node_tags,udp}`，创建时保存为快照；`host` 覆盖连接地址，`node_tags` 过滤节点，通配监听且无 `advertise`/`host` 的规则会被跳过。端口段展开为多个条目。只支持 Shadowsocks 入站；其他协议在预览的 `skipped` 中给出原因。

权限：读取列表/预览需要 `read`，创建/轮换/删除需要 `users:write`，并同时受账号角色与租户边界限制；只读用户不能写入。系统管理员可见全部，租户管理员可见本租户普通用户，普通用户只管理自己。令牌只保存 SHA-256 哈希；记录和索引写入 metadata，应用 schema 仍为 v5、恢复日志格式 4 不变。0.20.0 二进制忽略这些键，回退会丢失订阅服务但不会删除数据。详见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)。

## 0.22.0 DNS 托管记录与 DDNS

DNS 服务商、区域和记录保存在 metadata，schema 仍为 v5、恢复日志格式 4。所有 `/dns/*` 接口仅系统管理员，且只接受登录会话；API 令牌访问返回 403。服务商读取只返回 `token_set`，不返回令牌原文。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/dns/providers` | 服务商列表/创建 `{name,kind,endpoint,token}` |
| GET/PUT/DELETE | `/dns/providers/{id}` | 读取（脱敏）/更新（令牌留空保留）/删除；有区域时 409 |
| GET/POST | `/dns/zones` | 区域列表/创建 `{provider_id,name,mode,min_keep}` |
| GET/PUT/DELETE | `/dns/zones/{id}` | 读取/更新/删除；有记录时 409 |
| GET/POST | `/dns/zones/{id}/records` | 记录列表/创建 `{name,type,content,ttl,proxied,health?}` |
| GET/PUT/DELETE | `/dns/records/{id}` | 记录读取/更新/删除；应用模式删除时清理服务商记录 |
| POST | `/dns/zones/{id}/reconcile` | 观察或应用同步，返回创建/更新/删除/未变/保留/错误和逐条 action |
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
| POST | `/nodes/{node}/templates/{id}` | `{expected_revision,name,listen}` 应用为新规则 |
| POST | `/nodes/{node}/templates/{id}/preview` | `{name,listen}` 只校验并返回拟创建规则 |
| POST | `/templates/{id}/rollout` | `{batch_size,canary_percent?,rollback_on_failure?,targets:[...]}` 分批应用；首批比例可选 |
| POST | `/templates/{id}/rollouts/{rollout_id}/retry` | 只重试失败/未尝试节点，按当前修订重新应用 |

模板创建/更新校验规则主体；应用生成新 ID、名称、监听和计量周期，走正常配置修订校验。`/templates*` 与节点模板应用仅登录会话。详见 [TEMPLATES.md](TEMPLATES.md)。

## 0.40.0 MPTCP 诊断

`GET /api/v1/diagnostics/mptcp`（仅系统管理员、登录会话）返回 `platform/supported/enabled/probe_error/interfaces/routes/endpoints/active_connections/note`。Linux 探测 MPTCP socket 与 `/proc` 配置；非 Linux 返回 `supported=false`。这是观测，不是数据面。CLI：`relay mptcp-info`。详见 [MPTCP.md](MPTCP.md)。

## 0.44.0 UPnP CLI

`relay upnp-map --description-url URL --internal-client IP --internal-port N --external-port N [--lifetime-secs N] [--delete]`：读取 IGD description，选择 WANIPConnection/WANPPPConnection，调用 SOAP AddPortMapping/DeletePortMapping；不做 SSDP 发现。无 HTTP API。详见 [NAT.md](NAT.md)。

## 0.43.0 PCP CLI

`relay pcp-map --gateway IP[:PORT] --internal-port N [--external-port N] [--lifetime-secs N] [--delete]`：PCP v2 MAP UDP 单映射客户端，随机 nonce、IPv4-mapped 外部地址、生命周期上限 7 天。无 HTTP API。详见 [NAT.md](NAT.md)。

## 0.42.0 NAT-PMP CLI

`relay nat-map --gateway IP[:PORT] --internal-port N [--external-port N] [--lifetime-secs N] [--delete]` 管理一个 NAT-PMP UDP 映射；默认端口 5351，生命周期上限 7 天，`--external-port 0` 由网关分配。无 HTTP API。详见 [NAT.md](NAT.md)。
