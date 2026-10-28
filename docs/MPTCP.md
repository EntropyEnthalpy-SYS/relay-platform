# MPTCP rule transport and observations

The non-payment completion branch adds a real Linux MPTCP data path to managed rules. Set `mptcp` to `{ "inbound": "require", "outbound": "prefer" }`; each direction accepts `off`, `prefer` or `require`. `prefer` permits ordinary TCP when the kernel or peer cannot negotiate MPTCP. `require` rejects a connection unless negotiation is confirmed at setup. A later kernel fallback, if any, is visible in the next live observation; this setting is not an encryption or authentication policy.

All normal ACLs, accounting, quotas, rate limits, TLS, templates and configuration permissions still apply. UDP-only rules reject MPTCP. Source ACLs apply to the initial peer; additional MPTCP paths are controlled by the kernel path manager and authenticated by the MPTCP connection keys. Configure endpoint/network policy accordingly.

A listener's socket protocol cannot be changed in place: disable and publish the rule before changing its inbound mode and enabling it. Rejected updates preserve the previous revision and forwarding path. Outbound policy changes cancel affected sessions through the existing security-update lifecycle.

The rule editor exposes both policies. Node statistics include cumulative negotiated/fallback/rejection counts and at most 128 live socket observations, refreshed at each stats sample. These observations include the actual subflow total when the kernel supplies it, and socket byte counts distinct from billable payload. Old kernels return missing fields as null. Tracking adds at most 128 duplicate descriptors per engine; they close with their tunnel. The Prometheus endpoint exports MPTCP counters and the active socket count.

Linux acceptance has established a real relay flow with three kernel subflows over two disposable virtual Ethernet paths, then disabled its primary client interface. The same connection continued transferring correct data. Its persisted ledger contained exactly 2 MiB upload and 2 MiB download. This verifies subflows/failover, not WAN capacity or aggregation gain on independent physical links. Reproduce with `python3 scripts/check_linux_mptcp.py --binary PATH --workdir NEW_DIRECTORY` as root on a Linux test host. The harness only changes its own namespaces and removes them afterwards.

Explicit Linux Rust probes: `cargo test --locked --test managed_mptcp -- --test-threads=1 --include-ignored`. The two opt-in tests require enabled MPTCP. Ordinary cross-platform checks verify validation, TCP fallback, observer cleanup and preservation of the previous configuration after a rejected live mode change.

Endpoint and route provisioning remain a host/network management task in this stage; the panel does not yet provision kernel endpoints. End-to-end WAN acceptance and equal-condition throughput comparisons remain open.

Implementation references: [Linux socket API](https://docs.kernel.org/networking/mptcp.html), [kernel connection observations](https://www.mptcp.dev/mptcp-info.html), [path-manager configuration](https://www.mptcp.dev/pm.html).

## Historical capability-only interface


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
