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

## 界面与 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/templates` | 可见模板/创建 |
| PUT/DELETE | `/templates/{id}` | 编辑/删除，受租户范围 |
| POST | `/nodes/{node}/templates/{id}` | 应用为新规则 |
| POST | `/nodes/{node}/templates/{id}/preview` | 只校验并返回拟创建规则，不写修订 |

`/templates*` 和节点模板应用仅接受登录会话，API 令牌访问 403。面板规则表格的“存为模板”和“规则模板”页提供保存、应用、删除。

## 验证与限制

- Store 测试覆盖创建、列表、预览、应用生成新 ID/名称/监听/owner/tenant/meter、过期修订 409、viewer 403；预览不改变修订，重复监听返回 `valid=false`。
- HTTP 测试覆盖创建、viewer 403、节点配置修订、应用后规则名称。
- 未实现模板版本化、完整配置差异视图、变量参数化、跨节点灰度批次、模板引用依赖图、批量撤销和浏览器点击验收；模块 06 仍为部分实现。
