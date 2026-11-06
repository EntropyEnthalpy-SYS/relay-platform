# 端点组与转发链：按层复用的多跳转发

端点组（英文界面 Endpoint group）是转发链中的**一层候选服务器**；转发链（Chain）把端点组按顺序排成 1–6 层。用一条转发链新建转发时，路径为：客户端 → 入口服务器 → 第 1 层候选 → 第 2 层候选 → … → 最后一层候选 → 最终目标。它对应 Zero Forwarder 的“端点组”和“已保存的转发链”。

同一个端点组里的服务器**互为备选**，不是依次经过的多跳：上一跳按这一层的均衡方式在组内选择一台。需要经过几跳，就建几层，每层一个组。

转发链只是“生成规则的模板”。用它新建的转发由每台服务器上的**普通规则**组成（目标带 `via` 指向下一层服务器上的规则，见[拓扑](TOPOLOGY.md)），之后的修改、暂停、删除、健康检查和计量都与手工搭建的多跳转发相同。

## 数据与安全边界

- Agent 协议、发给 Agent 的规则格式都没有变化，旧版 Agent 照常运行。schema、恢复日志格式、备份和连续恢复也不变。控制器在 `metadata` 中另存三类记录：
  - `endpoint_group:<id>`：`{id, tenant_id, name, description, members:[node_id], created_at_ms, updated_at_ms}`，`members` 按操作者给出的顺序保存；
  - `forwarding_chain:<id>`：`{id, tenant_id, name, enabled, layers:[{group_id, balance}], created_at_ms, updated_at_ms}`；
  - `chain_use:<入口规则 id>`：`{chain_id, entry_node_id, layers:[[{node_id, rule_id}]]}`，记录一次“用转发链新建转发”在每层每台服务器上建出的规则。
- 端点组属于其成员服务器所在的租户，所有成员必须属于同一租户；转发链属于其端点组的租户，所有组必须属于同一租户；入口服务器也必须属于该租户。其他租户看不到这些记录，访问返回 404。
- 读取需要登录会话或带 `read` 的 API 令牌。新建、修改、删除、规划（plan）和应用（apply）需要可写角色，API 令牌还需 `nodes:write`；只读用户（viewer）返回 403。保存端点组时检查对每台成员服务器的写权限；应用时每台服务器的写权限、修订号和配置校验由配置发布路径检查。
- 应用在**一个事务**里分配端点、以一个配置批次（最多 64 台服务器）发布入口和每层的全部规则，并写入 `chain_use` 记录；任何一台失败则全部不变。
- 审计动作为 `endpoint_group.create`、`endpoint_group.update`（详情含修改前的成员）、`endpoint_group.delete`、`forwarding_chain.create`、`forwarding_chain.update`、`forwarding_chain.delete`（详情含遗忘的使用记录数）、`forwarding_chain.apply`（详情含入口与各层的规则）。发布本身仍记录 `config.publish`，涉及多台时另有一条 `config.batch_publish`。

## 限制与校验

| 项目 | 限制 | 违反时 |
| --- | --- | --- |
| 端点组成员 | 1–32 台、不重复、同一租户，名称 1–120 字节，说明最多 2000 字节 | 400 |
| 转发链层数 | 1–6 层，名称 1–120 字节 | 400 |
| 同一端点组 | 在一条转发链中只能作为一层 | 400 |
| 同一台服务器 | 不能出现在同一条转发链的两层中（经由两个不同的组也不行） | 新建 / 修改转发链 400；修改端点组导致某条使用它的转发链出现这种情况 409 |
| 入口服务器 | 不能是转发链中任一层的成员，必须属于转发链的租户 | 400，提示它在第几层 |
| 一次转发涉及的服务器 | 入口加全部层的成员最多 64 台（配置批次上限） | 400 |
| 停用的转发链 | 不能用来新建转发；重新启用后可以 | 409 |
| 转发链的某个组已删除，或组中某台服务器已删除 | 不能用来新建转发，需先编辑组或转发链 | 409 |
| 正被转发链使用的端点组 | 不能删除，需先从转发链中移除 | 409 |

## 用转发链新建转发

请求 `{entry_node_id, name, protocol, target, entry_port|null, owner_id?, expected_revisions?}`。`protocol` 为 `tcp`、`udp` 或 `both`；`target` 是最终目标（`主机:端口`，按普通规则目标校验）；`name` 为 1–100 字节。

规则图：

- 最后一层的每台服务器各得一条规则，目标为 `target`（权重 1），均衡方式为加权轮询。
- 第 i 层（i 不是最后一层）的每台服务器各得一条规则，目标是第 i+1 层**全部**服务器上的新规则：每个目标的地址为那台服务器分配到的公开地址（`advertise`），`via` 为 `{node_id, rule_id}`，权重 1；均衡方式取**第 i+1 层**的 `balance`。
- 入口服务器得到入口规则，目标是第 1 层全部服务器上的新规则，均衡方式取第 1 层的 `balance`。
- 因此第 i 层到第 i+1 层共有“第 i 层台数 × 第 i+1 层台数”条边。例如第 1 层 2 台、第 2 层 3 台时，入口有 2 个目标，第 1 层每条规则各有 3 个目标，第 2 层每条规则指向最终目标。
- 规则名为“`name` · 1”（入口）、“`name` · 2”（第 1 层）……依此类推；所有规则都是新规则（新编号、新计量周期），启用，没有配额、到期时间和限速；所有者为 `owner_id`，省略时为操作者。各服务器原有规则保持不变。
- 每层的 `balance` 可取 Relay 已有的均衡方式：`weighted_round_robin`（缺省，与引导式新建转发相同）、`source_hash`、`least_connections`、`lowest_latency`、`random`。`lowest_latency` 需要健康探测：控制器为按最低延迟选择的那条规则自动加上 TCP 连接探测（`{"tcp":{"kind":"connect"}}`）；因此只要有一层使用最低延迟，`protocol` 必须是 `tcp`，否则返回 400。
- 只生成普通 TCP / UDP 转发，与引导式新建转发的“原生 TCP / UDP”相同：节点之间不加 WS / WSS 隧道、TLS、PROXY 或多路径，也不创建受管协议网关。需要这些功能时，用引导式新建转发或在图示编辑器中修改已建成的规则。

端点（每台服务器的监听地址和公开地址）由与 `POST /configurations/allocate-endpoints` 相同的分配逻辑按路径顺序（入口，然后各层按组内顺序）给出：端口取服务器资料“转发设置”的端口范围中、已保存配置未占用的端口，地址取转发主机（有公网端口映射时换算）。`entry_port` 指定入口端口时，入口按该服务器转发设置的监听 IP 和转发主机手工设置端点；入口没有转发设置时返回 400。分配失败时：服务器没有转发地址返回 400；端口已被占用或端口范围已满返回 409。两种情况的错误体都带 `lines:[{node_id, error}]`，指出是哪台服务器。

### 规划与应用

- `POST /chains/{id}/plan` 返回 `{entry_rule_id, hops:[{layer, node_id, node_name, rule_id, listen, advertise}], batch:{updates:[{node_id, expected_revision, rules, rate_bytes_per_sec}]}, preview}`。`layer` 为 0 表示入口，1 起为各层；`batch` 是应用时将发布的配置批次，`preview` 是对它执行配置预览（与 `/configurations/preview` 相同的校验）的结果。规划**不写任何数据，也不预占端口**。
- `POST /chains/{id}/apply` 用同样的请求重新分配并发布，返回 `{entry_rule_id, hops, published}`。规则编号由应用重新生成，与规划中的不同。为保证“发布的就是预览的”，可把规划中每台服务器的 `expected_revision` 作为 `expected_revisions:{node_id: revision}` 一并提交（面板总是这样做）：涉及的服务器集合不同或任何一台的修订已变化时返回 409，并在 `lines` 中列出变化的服务器，不修改任何服务器。不带 `expected_revisions` 时按当前修订发布，发布路径仍在同一事务内检查修订。

## 使用记录与“组成员已变化”

每次应用写入 `chain_use:<入口规则 id>`。`GET /chains` 为每条转发链列出 `uses`：入口服务器与入口规则名称、每层每台服务器上的规则（规则或服务器已删除时 `missing:true`），以及 `out_of_date` 和 `changes:[{layer, added, removed}]`。

`out_of_date` 比较转发链**当前**各层端点组的成员与建成时各层的服务器：某层增加或移除了服务器即为已过期，只调整组内顺序不算。修改转发链的层（换组、增减层）同样会使已有转发显示为已过期。

**不会自动同步。** 修改端点组或转发链不会改变已经建成的转发，控制器只报告哪些转发已过期。要使用新的成员，请用转发链重新新建转发，确认后删除旧转发。

## 删除

- **删除服务器**：不受端点组和使用记录阻止（仍受其他规则 `via` 引用等原有检查约束）。端点组中该成员显示为已删除（`missing`），保存端点组时需将其移除；在此之前不能用包含它的转发链新建转发（409）。使用记录中对应的规则显示为已缺失。
- **删除端点组**：只删除记录，服务器和规则不受影响；仍被转发链使用时返回 409。
- **删除转发链**：删除转发链记录和它的使用记录，用它建成的规则全部保留为普通规则。修改转发链时，入口规则已不存在的使用记录被一并遗忘。
- **删除建成的转发**：与其他多跳转发相同，在“全部转发”中删除。

## API

| 方法 | 路径 | 请求 / 结果 |
| --- | --- | --- |
| GET | `/api/v1/endpoint-groups` | 可见的端点组：`[{id, tenant_id, name, description, members:[{node_id, node_name, missing}], used_by:[{id, name}], created_at_ms, updated_at_ms}]` |
| POST | `/api/v1/endpoint-groups` | `{name, description?, members:[node_id]}` → 端点组 |
| PUT | `/api/v1/endpoint-groups/{id}` | 同上，`members` 为完整的有序列表 |
| DELETE | `/api/v1/endpoint-groups/{id}` | `{ok:true}`；被转发链使用时 409 |
| GET | `/api/v1/chains` | 可见的转发链：`[{id, tenant_id, name, enabled, layers:[{group_id, group_name, balance, members:[{node_id, node_name, missing}]}], uses:[{entry_rule_id, entry_node_id, entry_node_name, name, missing, layers:[[{node_id, rule_id, node_name, missing}]], out_of_date, changes:[{layer, added, removed}]}], created_at_ms, updated_at_ms}]` |
| POST | `/api/v1/chains` | `{name, enabled?, layers:[{group_id, balance?}]}` → 转发链；`enabled` 缺省 true，`balance` 缺省 `weighted_round_robin` |
| PUT | `/api/v1/chains/{id}` | 同上，`layers` 为完整的有序列表；不改变已建成的转发 |
| DELETE | `/api/v1/chains/{id}` | `{ok:true}`；规则保留 |
| POST | `/api/v1/chains/{id}/plan` | `{entry_node_id, name, protocol, target, entry_port\|null, owner_id?}` → `{entry_rule_id, hops, batch, preview}`；不写任何数据 |
| POST | `/api/v1/chains/{id}/apply` | 同上，可加 `expected_revisions` → `{entry_rule_id, hops, published}`；一个批次，全部成功或全部不变 |

请求体与其他接口相同：JSON 语法错误返回 400，未知字段、缺少必填字段或取值无效（例如未知的均衡方式）返回 422。错误：输入无效 400，权限 403，不存在或不可见 404，冲突 409（端口被占用或已满、修订已变化、转发链已停用、组或成员已删除、组正被使用、修改组会使服务器出现在两层）。能确定原因所在服务器时，错误体带 `lines`：

```json
{"error": "cannot allocate endpoints: hk-entry: port 26000 is already used on this server",
 "lines": [{"node_id": "…", "error": "port 26000 is already used on this server"}]}
```

## 面板

「转发规则」的“全部转发”页面下方、“共同规则”之后是“端点组与转发链”区块：

- **端点组**：“＋ 新建端点组”填写组名称、说明和“成员服务器（按顺序）”，可“上移”“下移”“移除”和“添加服务器”。列表显示成员（已删除的服务器标为“服务器已删除”）和“使用此组的转发链”，以及“编辑”“删除”。
- **转发链**：“＋ 新建转发链”填写转发链名称、“启用：可以用此链创建新的转发”，并逐层选择“第 N 层 · 端点组”和“上一跳在这一层中的选择方式”，可“＋ 添加层”“移除此层”。列表显示各层的组、候选服务器和选择方式，“用此链创建的转发”（已过期的标为“组成员已变化”，并列出各层新增和移除的服务器），以及“用此链新建转发”“编辑”“删除”。
- **新建转发**：“＋ 新建转发”的选择页中有“按已保存的转发链 → 使用已保存的转发链”。表单选择转发链、入口服务器（只列出转发链租户中链外的服务器）、转发名称、传输协议、最终目标和可选的入口端口，并以表格列出各层候选。“预览发布内容”调用 plan，用与引导式新建转发相同的预览页显示整条路径图和逐台变更；“发布这些变更”调用 apply 并带上预览时的修订号。
- “全部转发”中由转发链建成的转发显示“转发链 · 名称”，已过期时另显示“组成员已变化”。

## 验证与限制

- `crates/relay-platform/tests/chains.rs` 7 项集成测试：
  - `plan_builds_every_layer_towards_every_server_of_the_next_layer`：入口、第 1 层 2 台（来源 IP 哈希）、第 2 层 3 台（最少连接）的不对称转发链，核对每条规则的目标、`via`、地址和均衡方式、按转发设置分配的端点（含跳过已占用端口与指定入口端口）、已有规则保留，以及规划不写数据；
  - `apply_publishes_every_server_in_one_batch_and_records_the_use`：一个批次发布 6 台、发布后的边、使用记录、第二次新建取下一个空闲端口、删除转发链保留规则；
  - `a_failure_on_one_server_publishes_nothing`：入口端口被占用、最后一层端口范围已满、规划后某台服务器修订变化，三种失败都不修改任何服务器且指出出错的服务器；
  - `chains_groups_and_entries_are_validated`：服务器在两层、入口在链内、组成员数量与重复、无效目标和端口、修改组导致重叠、删除被使用的组、停用的转发链、最低延迟的连接探测与 UDP 拒绝、层数上限、跨租户的组和入口、删除成员服务器；
  - `a_use_is_out_of_date_after_its_groups_change`：组成员增减后报告已过期及变化、只调整顺序不算、删除入口服务器后显示已缺失；
  - `tenants_are_isolated_and_viewers_cannot_change_chains`：租户隔离（404）和只读用户 403；
  - `the_api_plans_and_applies_a_chain_with_token_scopes`：HTTP 接口的规划、应用、逐服务器 409、只有 `read` 的令牌可读不可规划而 `nodes:write` 可以、删除被使用的组 409。
- `scripts/test_web_chains.cjs` 在中英文下运行面板代码，核对端点组和转发链的新建、编辑、删除，以及“使用已保存的转发链”的 plan 与 apply 发送的请求。
- 保存成功只表示期望配置已提交；各服务器是否已应用、防火墙是否放行所示端口、路径是否可达，仍需在“节点应用状态”和客户端确认。
- 不支持：已建成转发随端点组自动同步、节点间 WS / WSS / TLS / PROXY / 多路径、受管协议网关、端口段、最终目标多于一个。最后一层到最终目标固定为加权轮询。
