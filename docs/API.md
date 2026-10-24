# 开发版 API 契约

基础路径 `/api/v1`，JSON。用户与节点分别使用独立的 256-bit 随机 Bearer 凭据；持久化存储只保存服务端令牌哈希。用户会话八小时过期。Agent 的长期凭据保存在自己的私有状态库。所有跨机器请求须通过 HTTPS。

API 尚处开发阶段；以 `model.rs`、`lease.rs` 等公开模型的严格字段定义为准。未识别字段返回错误，不能假装启用尚未实现的功能。单次请求限制 2 MiB。

| 方法 | 路径 | 请求或用途 |
| --- | --- | --- |
| POST | `/auth/login` | `{username,password}` → `{token,user,expires_in_seconds}` |
| GET | `/session` | 当前用户与角色 |
| POST | `/auth/logout` | 撤销当前会话 |
| GET / POST | `/nodes` | 列出可见节点；`{name,tenant_id?,lease_policy?}` 创建节点并返回一次性注册令牌 |
| GET | `/nodes/{id}/config` | 当前期望配置，包含修订号和规则 |
| PUT | `/nodes/{id}/config` | `{expected_revision,rules}`；并发冲突返回 409，成功生成下一版本 |
| GET | `/nodes/{id}/health` | 实际修订对应的目标健康、年龄、候选原因、探测流量与容量；按节点权限过滤 |
| GET | `/nodes/{id}/history` | 最近 100 次配置修订 |
| POST | `/nodes/{id}/rollback` | `{revision,expected_revision}`；把历史规则作为新修订发布，账本不回滚 |
| GET | `/topology` | 当前可见节点、配置、声明边、根规则及应用状态 |
| POST | `/configurations/preview` | `{updates:[{node_id,expected_revision,rules}]}`；只读校验并返回候选配置及完整差异，需要写权限 |
| POST | `/configurations/publish` | 同预览请求；1..64 个节点的期望配置在同一事务中提交 |
| GET / POST | `/users` | 列出用户；`{username,password,role,tenant_id?}` 创建用户 |
| POST | `/users/{id}/revoke-sessions` | 撤销该用户全部现有 Web 会话 |
| POST | `/tenants` | `{name}`；仅系统管理员 |
| GET | `/usage` | 最近 2,000 条已上报的规则/周期累计记录，不是全库聚合接口 |
| GET / POST | `/budgets` | 返回 `{allocation_paused,budgets}`；创建 `{scope,scope_id,name,limit_bytes,quantum_bytes}` |
| PUT | `/budgets/{id}` | `{expected_revision,limit_bytes,quantum_bytes}`；修改额度，不清零用量 |
| GET | `/audit` | 最近 200 条全局审计；仅系统管理员 |
| GET | `/recovery` | `{enabled,healthy,head}`；仅系统管理员，读取控制器恢复日志状态 |
| GET | `/control/metrics` | 仅系统管理员；返回本次控制器运行的节点同步统计 |
| GET | `/capabilities` | 实现能力与待实现能力目录，不代表完整发布验收 |
| POST | `/agent/enroll` | `{node_id,enrollment_token,credential}`；返回 `{enrolled:true}` |
| POST | `/agent/reconcile` | 节点凭据认证；分页获取权威用量下限和相同修订的配置 |
| POST | `/agent/sync` | 节点凭据认证，上报用量/状态并获取期望配置 |

注册时 Agent 先在本地生成并持久化独立 `credential`，然后请求控制器绑定。一次性令牌只允许首次绑定；相同已绑定凭据可以重试确认，原注册令牌不能绑定第二个凭据。控制器不需要保存可还原的节点秘密。Node 注册后的令牌复制或凭据轮换属于后续身份生命周期功能。

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

响应包含 `controller_instance`、可选 `config`、`acknowledgements`、`server_time_ms`。`controller_instance` 每次 API 服务启动变化，在线 Agent 据此重新对账并补报曾确认的数据。每批最多 1,024 条累计用量；只有规则/周期属于该节点才可入账。同序号与同累计值可以重放；序号或字节倒退、同序号改值返回 409。确认到旧序号不会清除后来新增长的未确认字节。

规则、流量与配置修订的数据库整数上限为有符号 64 位范围。API 使用 JSON 整数，精确处理超过 `2^53-1` 的数值时，客户端须使用无损整数解析；浏览器配额输入仅接受 JavaScript 安全整数，界面显示经过单位换算的近似值。

恢复请求格式为 `{ledger_id:null,after:null,expected_revision:null}`；首次由控制器分配或返回该节点既有账本 ID。返回 `{node_id,ledger_id,revision,usage,next,config}`。后续请求携带同一 `ledger_id`、上一页 `next` 对象及 `expected_revision`。每页最多 256 条历史计量周期，按 `(rule_id,meter_epoch)` 排序，最后一页 `next:null` 且包含同一修订的 `config`。分页期间配置变化返回 412，Agent 重头对账；单次恢复最多 4096 页，超过则拒绝激活并要求处理归档。

本地较旧的累计值在未开始转发时提高到控制器确认值；本地较新且向量单调的值保留并重新补报。对账只降低“确认序号”，不降低已接纳计量。相同序号不同值、较新序号出现任一方向倒退、账本身份不一致都会失败，不以简单取最大值掩盖分叉。在正常离线重启已经转发的情况下，若远端反而领先，Agent 停止转发并要求恢复，避免与在途数据混合。

恢复标记只在完成全部账本分页并成功应用配置后清除。历史上已删规则的用量只作为禁用计量行恢复；不能因此开启历史规则。真实身份或历史分叉导致的 409 不会自动修改；不能删库绕过。

TLS 配置使用 `Rule.inbound_tls={identity,client_ca}` 与 `Target.tls={server_name,ca,identity}`，未设置则为普通流量。所有 ID 引用节点本地材料，API 不接收 PEM 私钥；入口/出口 TLS 不接受 UDP 或双协议，也不接受一条规则中明文与加密出口混用。节点材料错误通过 `apply_error` 报告，期望修订和实际修订会保持不同。

额度的 `scope` 为 `user`、`tenant` 或 `node`，每个对象只允许一个额度。`quantum_bytes` 范围为 1..67108864，单位字节。创建需要相关节点确认停用规则；更新需要修订号一致，且新总额不能低于 `committed_bytes`。`consumed_bytes` 是已上报累计接纳量；`committed_bytes-consumed_bytes` 是包含未上报消费的剩余预留，不等于可重新发放的余额。读取按租户隔离，创建和修改需要写权限，均有审计记录。

规则上的 `budget_ids` 由控制器按当前 owner/tenant/node 自动重算；用户提交和历史回滚无法删除适用的预算。0.4.0 Agent 同步可带 `budget:{run_id,requests,reports,settle_only}`。`requests` 每项为 `{budget_id,request_id,minimum_bytes}`；`reports` 每项为 `{grant_id,consumed_bytes,surrender}`。响应的 `budget` 包含 `grants`、`acknowledgements`、`allocation_paused`、`cancelled_requests`；每项 grant 为 `{grant_id,budget_id,request_id,run_id,bytes}`，确认项与 report 同形，取消项为请求 ID。三个响应集合各最多 1024 项；请求和报告也各最多 1024 项。最小请求最大 65536 字节，用于完整 UDP 包。`request_id` 在节点/运行范围内幂等；报告为单调累计值，封存后不得增加。已发出的预留只有节点先持久化封存，才允许归还未用部分。

`settle_only:true` 不发放新额度，但返回已经发出而响应可能丢失的预留；尚未发放的请求会记录取消状态，即使原请求随后到达也不再分配。已停用规则的待确认请求同样需要结算。Agent 收到旧请求的预留后，先持久化封存，再用下一轮报告归还。新增字段使用默认值便于缺省解析，但 0.3.0 严格 JSON 客户端不接受 0.4.0 新字段，因此控制器与 Agent 应协调升级。

创建额度和恢复的完整约束见 [BUDGETS.md](BUDGETS.md)。当前未提供额度删除、周期清零或 HTTP 恢复解除接口；`allocation_paused:true` 时不发放新预留。0.4.0 的离线 `relay restore` 只有在完整恢复日志校验和重放成功后，才恢复原分配状态，见 [RECOVERY.md](RECOVERY.md)。接口的可用能力目录不表示完整灾难恢复已经完成。

`/recovery` 的 `head` 包含 `journal_id`、`schema`、`schema_sha256`、`sequence`、`sha256` 和 `committed_bytes`。它不返回日志内容、磁盘路径或凭据。未认证的 `/healthz` 在恢复写入故障后返回 503 及 `status:recovery_log_unavailable`；正常为 200。该检查判断本机日志写入状态，不代表已完成异地备份或业务线路健康。

401 表示凭据失效；403 表示权限或归属错误；不可见节点返回 404；400/422 表示输入不合法；409 表示版本/账本冲突；412 表示恢复分页期间配置变化。内部错误返回通用消息，细节进入本地服务日志。

0.5.0 的 `/agent/sync` 在控制器内最多等待 2 ms 合并，单批最多 16 项，等待队列最多 64 项；不是客户端批量接口。满队列返回 429，未入队请求不执行写入。认证、账本和额度检查仍在每项请求的事务保存点内执行；预期输入错误只回滚该项，磁盘或日志错误使整批不返回成功。响应丢失后继续使用原来的幂等请求 ID。管理员其他写入继续独立提交。

`/control/metrics` 字段为 `committed_batches`、`processed_requests`、`largest_batch`、`queue_full_rejections`、`failed_batches`、`batch_limit`、`queue_capacity`、`coalesce_window_ms`。计数在控制器重启时清零，不是流量账本；`processed_requests` 包含完成校验后返回预期错误的请求，整批提交失败单独计入 `failed_batches`。没有数据变更的批次可以不产生日志记录。`/usage` 在上报时间相同的情况下，再按节点、规则、周期稳定排序。

## 0.6.0 路由字段

规则新增可选 `listen_end_port`、`port_mapping`、`outbound_bind`、`dns_cache`；完整合同及示例见 [ROUTING.md](ROUTING.md)。旧字段默认值保持兼容，SQLite schema 仍为 v4。0.5 Agent 会拒绝带新字段的配置，因此先升级节点，再发布新能力。IPv6 监听现在明确设为仅 IPv6，双栈需要两条监听规则。

## 0.7.0 PROXY 字段

规则新增 `inbound_proxy={version,trusted_sources,placement,max_header_bytes}`；每个目标新增 `proxy_protocol={version,placement,checksum}`。字段、默认值、TLS 顺序、可信对端与来源 ACL 的区别、UDP 逐包语义见 [PROXY.md](PROXY.md)。未知字段和不支持的协议组合会被拒绝；节点实际应用失败继续通过 `apply_error` 返回。SQLite schema v4 不变，0.6 Agent 应先升级再发布新字段。

能力目录新增 `proxy-protocol-tcp-v1-v2`、`proxy-protocol-udp-v2`、`udp-destination-tracking`。它们表示代码实现能力，不表示已经通过 Linux、外部 UDP/TLS 互通或生产压力验收。

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
