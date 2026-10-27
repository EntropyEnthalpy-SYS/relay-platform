# MPTCP 能力观测

0.40.0 增加 MPTCP 内核能力与网络配置观测，作为模块 04 的入口。**这不是 MPTCP 数据面实现**，也不把“开关开启”当作聚合成功。

## 能力探测

`relay mptcp-info` 与 `GET /api/v1/diagnostics/mptcp`（仅系统管理员）返回同一结构：

```json
{
  "platform": "macos",
  "supported": false,
  "enabled": null,
  "probe_error": "MPTCP socket capability is probed on Linux only",
  "interfaces": [],
  "routes": [],
  "endpoints": [],
  "active_connections": null,
  "note": "Capability and configuration observation only; ..."
}
```

Linux 上：

- 用 `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)` 探测内核是否允许创建 MPTCP socket；失败时保留 `probe_error`。
- 读取 `/proc/sys/net/mptcp/enabled`、`/proc/sys/kernel/osrelease`（`enabled` 缺失时为 `null`）。
- 读取 `/sys/class/net/*/operstate` 接口、`/proc/net/route` 路由（最多 128 条）、`/proc/net/mptcp` 端点行（最多 128 行）。
- `active_connections` 固定为 `null`：当前没有 MPTCP 数据面，不能虚构子流/连接状态。

非 Linux 平台返回 `supported=false` 和明确的 `probe_error`，不猜测能力。

## 验证与限制

- 单元测试确认平台字段、note、非 Linux 明确不支持；HTTP 测试确认管理员可读、viewer 403。
- 未实现 MPTCP 端点配置、子流建立/观测、接口选择、路由策略、连接状态和普通 TCP 回退观测；模块 04 仍为部分实现。
- 该报告不会改变任何规则、监听或转发路径；不能据此宣称 MPTCP 已可用。
