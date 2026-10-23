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
| GET | `/audit` | 最近 200 条全局审计；仅系统管理员 |
| GET | `/capabilities` | 实现能力与待实现能力目录，不代表完整发布验收 |
| POST | `/agent/enroll` | `{node_id,enrollment_token,credential}`；返回 `{enrolled:true}` |
| POST | `/agent/sync` | 节点凭据认证，上报用量/状态并获取期望配置 |

注册时 Agent 先在本地生成并持久化独立 `credential`，然后请求控制器绑定。一次性令牌只允许首次绑定；相同已绑定凭据可以重试确认，原注册令牌不能绑定第二个凭据。控制器不需要保存可还原的节点秘密。Node 注册后的令牌复制或凭据轮换属于后续身份生命周期功能。

同步请求：

```json
{
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

响应包含可选 `config`、`acknowledgements`、`server_time_ms`。每批最多 1,024 条累计用量；只有规则/周期属于该节点才可入账。同序号与同累计值可以重放；序号或字节倒退、同序号改值返回 409。确认到旧序号不会清除后来新增长的未确认字节。

规则、流量与配置修订的数据库整数上限为有符号 64 位范围。API 使用 JSON 整数，精确处理超过 `2^53-1` 的数值时，客户端须使用无损整数解析；浏览器配额输入仅接受 JavaScript 安全整数，界面显示经过单位换算的近似值。

409 账本冲突的自动修复尚未实现，不能删除节点数据库绕过错误。旧备份和控制器不同步时需先做权威账本对账。

401 表示凭据失效；403 表示权限或归属错误；不可见节点返回 404；400/422 表示输入不合法；409 表示版本/账本冲突。内部错误返回通用消息，细节进入本地服务日志。
