# 规则模板

0.38.0 增加规则模板库，补齐配置编排中的模板子项。

## 模型

模板保存一份已验证的规则主体（目标、协议、TLS/WS/PROXY、ACL、限额等），加上名称、说明和可选租户范围：

```json
{"tenant_id": null, "name": "Web preset", "description": "", "rule": { ... }}
```

- 全局模板（`tenant_id=null`）仅系统管理员创建；租户管理员只能创建/编辑/删除本租户模板。
- 查看按租户过滤；普通用户没有写权限。
- 创建/更新时调用规则校验；目标、监听、端口段、代理入口等错误会在保存前拒绝。
- 模板保存的是规则内容，不保存节点状态或历史账本。

## 应用

`POST /nodes/{node}/templates/{id}`：

```json
{"expected_revision": 7, "name": "Clone", "listen": "127.0.0.1:19090"}
```

- 复制模板规则，生成新的规则 ID、名称、监听地址、`meter_epoch`，设置节点租户和当前操作者为 owner，启用规则，清除模板中的 `listen_end_port`。
- 通过既有 `set_config` 修订检查、监听冲突/引用校验和节点权限执行；并发编辑的旧修订返回 409，不会覆盖。
- 配置发布后仍需节点回执确认实际应用；模板应用不直接修改运行中的节点。

## 预览

`POST /nodes/{node}/templates/{id}/preview`：

```json
{"name": "Clone", "listen": "127.0.0.1:19090"}
```

返回与“应用”相同的拟创建规则身份（新 ID、名称、监听、owner、tenant、meter）以及 `current_revision/valid/error`，但不写修订。监听冲突等校验错误会以 `valid=false` 和错误文本返回。预览不会改变节点配置或运行状态。

## 版本差异

`GET /templates/{id}/diff?from=1&to=2` 返回两个模板版本的结构化差异：

- 比较名称、描述、规则和变量；
- 路径使用 JSON Pointer 风格（`/rule/targets/0/address`），对象键转义 `~0`/`~1`；
- 数组按索引比较，新增/删除一侧为 `null`；
- 最多返回 512 个变化，避免超大输出；
- 面板“差异”按钮可输入两个版本号查看结果。

## 版本历史与回滚

- 创建为 v1；每次更新把当前模板快照写入 `template-version:{id}:{version}`，新内容版本号 +1。
- `GET /templates/{id}/versions` 返回当前及历史版本（新到旧）；历史快照不可变。
- `POST /templates/{id}/versions/{version}/rollback` 把旧内容作为**新版本**写回（版本号继续增加），不是删除历史或降级版本号。全局模板只能由系统管理员回滚；租户管理员回滚自己的模板时，当前对象和恢复快照都必须属于该租户。
- 只能回滚到严格更旧的版本；回滚需要管理员权限并写审计。
- 应用/批量可传 `template_version` 固定使用某个历史版本；单次应用省略时使用最新版本；批量应用在开始时固定版本，后续批次及重试沿用。固定版本按快照渲染，版本不存在或未来版本会拒绝。
- 模板版本与节点配置修订是两套独立计数。
- 面板模板页“版本”按钮列出历史并提供回滚。

## 应用回执门控

`wait_for_apply_ms` 可选：每批配置写入后等待目标节点的 `desired_revision` 和 `applied_revision` 都等于本次发布修订，且无 `apply_error`，超过时限则 `aborted` 并记录 `gate_error`。范围为 1–60000 ms。期望修订被后续修改取代时立即失败；不会接受更大的修订号。它只验证**配置应用回执**，不检查流量、错误率或延迟。

`require_target_health: true` 可选：每批应用后，轮询该批节点的 `target_health`，要求节点期望修订和已应用修订都精确等于本次修订、无应用错误、存在**本次规则 ID** 的报告、报告时间在 `max_age_ms` 内且所有该规则报告 `eligible=true`；超时（默认 5 秒，或 `wait_for_apply_ms`）则 `aborted` 并记录 `gate_error`。旧规则、过期或未来时间戳遥测不能通过门控；较新修订即使保留规则 ID 也不能代替本次修订。它复用 Agent 的探测结果，不等同于完整流量健康或自动放量。

## 健康预检

`require_healthy: true` 时，每个目标在应用前必须：

- 最近 90 秒内同步过；
- 没有 `apply_error`。

不满足的节点不会写入配置，报告对应错误并停止后续批次；这是**预检**，不是应用后的业务健康检查或自动放量。默认关闭。

## 百分比首批

`POST /templates/{id}/rollout` 可传 `canary_percent`（1–100）：

- 首批大小按 `ceil(目标数 × 百分比 / 100)` 计算，至少 1，且不超过 `batch_size`；
- 首批成功后，其余按 `batch_size` 分批；
- 首批失败仍按既有策略停止/可选回滚；
- 这是**批次大小**控制，不是健康检查或自动放量；没有观察窗口、错误率或延迟阈值。

## 变量替换

模板规则中的字符串字段支持 `{{name}}` 占位符，变量在模板创建时保存：

```json
{"name":"Origin template","rule":{"targets":[{"address":"{{host}}:{{port}}",...}],...},
 "variables":{"host":"origin.internal","port":"443"}}
```

- 变量名 1–64 字节 ASCII 字母/数字/下划线；值 ≤1024 字节且不能含控制字符；最多 64 个。
- 创建/更新模板时会用变量渲染并做完整规则校验；未解析的占位符直接拒绝，不会静默变成字面量。
- 应用模板可传 `variables` 覆盖默认值；同一模板可对不同节点使用不同 host/port 等。
- 批量应用每个目标也可带 `variables`；重试沿用原目标变量。
- 占位符可出现在任意字符串字段（包括目标、名称、TLS 名称等）；不处理数字/布尔字段。

## 批量应用（canary）

`POST /templates/{id}/rollout`：

```json
{"batch_size": 2, "rollback_on_failure": true, "targets": [
  {"node_id":"node-a","expected_revision":3,"name":"Web","listen":"127.0.0.1:19090"},
  {"node_id":"node-b","expected_revision":3,"name":"Web","listen":"127.0.0.1:19090"}
]}
```

- 目标按输入顺序分批，`batch_size` 1–50，最多 100 个节点；节点不能重复。
- 每个节点仍按自己的 `expected_revision` 应用，生成新的规则 ID/名称/监听/计量周期。
- 一批中任一节点失败即停止后续批次；默认同批已成功节点保留。请求可选 `rollback_on_failure=true`，按成功应用的反序移除本次 rollout 创建的规则；回滚失败逐节点报告，不隐藏。
- 返回 `batch/batches/applied/rolled_back/rollback_failed/aborted/results`；每项包含 revision、rule_id、`rolled_back` 或错误。回滚使用应用后的修订作为 expected revision，后续并发配置变更会使该项回滚失败。
- 面板模板页“批量应用”接受目标 JSON 和批大小，显示逐节点结果。

## 重试与恢复（0.97.0）

`POST /templates/{id}/rollouts/{rollout_id}/retry`：

- 每次完成的尝试持久化全部有序目标、固定模板版本、选项、规则 ID、修订与结果；记录通过 `root_id/retry_id` 关联。
- 从原始首批重新检查完整目标集。已有且未回滚的规则复用原 ID 和修订，重新检查所选回执/健康门控；不会因 `applied=true` 跳过失败 canary，也不会重复追加规则。
- 未发布或已成功回滚的节点按当前配置修订发布同一模板版本。已发布规则的修订若被改动，停止并要求操作者对账，避免覆盖并发配置或再追加一份规则。回滚失败同样保留原规则身份。
- 同一个根记录的并发重试返回 409；重试根记录或任意历史尝试时均沿链找到最新结果。最新尝试成功后，再重试返回同一报告，不再写配置。重启后可恢复**已经持久化的尝试记录**。
- 新字段 `acknowledged/healthy/completed/reused` 区分精确修订回执、规则健康、通过本次所选门控和复用已有发布；`applied` 为兼容字段，仍只表示发布过配置，不代表节点已执行。未选择回执/健康门控时 `completed=true` 仅表示配置发布完成。
- 0.96 记录缺失新字段可反序列化为默认值。旧记录未固定模板版本且模板已超过 v1 时返回 409，必须先对账再新建批量；不能猜测当时使用的模板内容。
- UI 每次失败后都可再次重试。发布进行中的进程崩溃尚无逐节点操作日志；未完成报告的发布须人工核对，不能宣称崩溃中途的 exactly-once。

## 界面与 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/templates` | 可见模板/创建 |
| PUT/DELETE | `/templates/{id}` | 编辑/删除，受租户范围 |
| POST | `/nodes/{node}/templates/{id}` | 应用为新规则 |
| POST | `/nodes/{node}/templates/{id}/preview` | 只校验并返回拟创建规则，不写修订 |
| GET | `/templates/{id}/versions` | 当前和历史模板版本 |
| GET | `/templates/{id}/diff?from=&to=` | 两个模板版本的结构化差异 |
| POST | `/templates/{id}/versions/{version}/rollback` | 旧内容作为新版本写回 |
| POST | `/templates/{id}/rollout` | 有序分批应用；可选首批比例、健康预检、应用回执等待、回滚 |
| POST | `/nodes/{node}/templates/{id}` | `{expected_revision,name,listen,variables?,template_version?}` 应用模板；可固定历史版本 |
| POST | `/templates/{id}/rollouts/{rollout_id}/retry` | 从原首批重新检查；复用已发布规则，恢复剩余目标 |

`/templates*` 和节点模板应用仅接受登录会话，API 令牌访问 403。面板规则表格的“存为模板”和“规则模板”页提供保存、应用、删除。

## 验证与限制

- Store 测试覆盖创建、列表、预览、应用生成新 ID/名称/监听/owner/tenant/meter、过期修订 409、viewer 403、预览不改变修订、重复监听 `valid=false`、canary 批次失败后停止后续节点，以及回执/健康失败重试、重启恢复、重复重试不复制规则和新修订不能替代原门控。
- HTTP 测试覆盖创建、viewer 403、节点配置修订、应用后规则名称。
- 自动回滚只覆盖本次 rollout 新建规则的移除，不做旧配置的全量快照恢复；未实现依赖图、批量撤销和浏览器点击验收；目标健康门控检查新规则、修订与报告时效，但仍是 Agent 探测结果，不检查真实业务流量；模块 06 仍为部分实现。
