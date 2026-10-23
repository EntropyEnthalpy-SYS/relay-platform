# 开发版 API 契约

基础路径 `/api/v1`，JSON。用户与节点分别使用独立的 256-bit 随机 Bearer 凭据；持久化存储只保存服务端令牌哈希。用户会话八小时过期。Agent 的长期凭据保存在自己的私有状态库。所有跨机器请求须通过 HTTPS。

API 尚处开发阶段；以 `model.rs` 的严格字段定义为准。未识别字段返回错误，不能假装启用尚未实现的功能。单次请求限制 2 MiB。

| 方法 | 路径 | 请求或用途 |
| --- | --- | --- |
| POST | `/auth/login` | `{username,password}` → `{token,user,expires_in_seconds}` |
| GET | `/session` | 当前用户与角色 |
| POST | `/auth/logout` | 撤销当前会话 |
| GET / POST | `/nodes` | 列出可见节点；`{name,tenant_id?}` 创建节点并返回一次性注册令牌 |
| GET | `/nodes/{id}/config` | 当前期望配置，包含修订号和规则 |
| PUT | `/nodes/{id}/config` | `{expected_revision,rules}`；并发冲突返回 409，成功生成下一版本 |
| GET | `/nodes/{id}/history` | 最近 100 次配置修订 |
| POST | `/nodes/{id}/rollback` | `{revision,expected_revision}`；把历史规则作为新修订发布，账本不回滚 |
| GET / POST | `/users` | 列出用户；`{username,password,role,tenant_id?}` 创建用户 |
| POST | `/users/{id}/revoke-sessions` | 撤销该用户全部现有 Web 会话 |
| POST | `/tenants` | `{name}`；仅系统管理员 |
| GET | `/usage` | 最近 2,000 条已上报的规则/周期累计记录，不是全库聚合接口 |
| GET / POST | `/budgets` | 返回 `{allocation_paused,budgets}`；创建 `{scope,scope_id,name,limit_bytes,quantum_bytes}` |
| PUT | `/budgets/{id}` | `{expected_revision,limit_bytes,quantum_bytes}`；修改额度，不清零用量 |
| GET | `/audit` | 最近 200 条全局审计；仅系统管理员 |
| GET | `/recovery` | `{enabled,healthy,head}`；仅系统管理员，读取控制器恢复日志状态 |
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

0.3.0 的 `scope` 为 `user`、`tenant` 或 `node`，每个对象只允许一个额度。`quantum_bytes` 范围为 1..67108864，单位字节。创建需要相关节点确认停用规则；更新需要修订号一致，且新总额不能低于 `committed_bytes`。`consumed_bytes` 是已上报累计接纳量；`committed_bytes-consumed_bytes` 是包含未上报消费的剩余预留，不等于可重新发放的余额。读取按租户隔离，创建和修改需要写权限，均有审计记录。

规则上的 `budget_ids` 由控制器按当前 owner/tenant/node 自动重算；用户提交和历史回滚无法删除适用的预算。0.4.0 Agent 同步可带 `budget:{run_id,requests,reports,settle_only}`。`requests` 每项为 `{budget_id,request_id,minimum_bytes}`；`reports` 每项为 `{grant_id,consumed_bytes,surrender}`。响应的 `budget` 包含 `grants`、`acknowledgements`、`allocation_paused`、`cancelled_requests`；每项 grant 为 `{grant_id,budget_id,request_id,run_id,bytes}`，确认项与 report 同形，取消项为请求 ID。三个响应集合各最多 1024 项；请求和报告也各最多 1024 项。最小请求最大 65536 字节，用于完整 UDP 包。`request_id` 在节点/运行范围内幂等；报告为单调累计值，封存后不得增加。已发出的预留只有节点先持久化封存，才允许归还未用部分。

`settle_only:true` 不发放新额度，但返回已经发出而响应可能丢失的预留；尚未发放的请求会记录取消状态，即使原请求随后到达也不再分配。已停用规则的待确认请求同样需要结算。Agent 收到旧请求的预留后，先持久化封存，再用下一轮报告归还。新增字段使用默认值便于缺省解析，但 0.3.0 严格 JSON 客户端不接受 0.4.0 新字段，因此控制器与 Agent 应协调升级。

创建额度和恢复的完整约束见 [BUDGETS.md](BUDGETS.md)。当前未提供额度删除、周期清零或 HTTP 恢复解除接口；`allocation_paused:true` 时不发放新预留。0.4.0 的离线 `relay restore` 只有在完整恢复日志校验和重放成功后，才恢复原分配状态，见 [RECOVERY.md](RECOVERY.md)。接口的可用能力目录不表示完整灾难恢复已经完成。

`/recovery` 的 `head` 包含 `journal_id`、`schema`、`schema_sha256`、`sequence`、`sha256` 和 `committed_bytes`。它不返回日志内容、磁盘路径或凭据。未认证的 `/healthz` 在恢复写入故障后返回 503 及 `status:recovery_log_unavailable`；正常为 200。该检查判断本机日志写入状态，不代表已完成异地备份或业务线路健康。

401 表示凭据失效；403 表示权限或归属错误；不可见节点返回 404；400/422 表示输入不合法；409 表示版本/账本冲突；412 表示恢复分页期间配置变化。内部错误返回通用消息，细节进入本地服务日志。
