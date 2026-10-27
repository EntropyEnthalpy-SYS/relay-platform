# 本地验证记录

0.91.0 开发版在 macOS 27.0.1 arm64 通过 **412 项自动化测试（383 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 413 项。日志见 [verification-0.91.0.txt](verification-0.91.0.txt)，逐项清单见 [validation-evidence-0.91.0.json](validation-evidence-0.91.0.json)。

## 0.91.0 反向 mux 公网 TLS

| 检查 | 结果 |
| --- | --- |
| 参数 | `--public-tls-cert/--public-tls-key` 成对 |
| 握手 | 公网 accept 后、OPEN 前完成 |
| 组合 | 可与控制 TLS/mTLS 同时启用 |
| 限制 | 无按流 ACL/计量/重放保护 |

## 0.90.0 反向 mux mTLS（历史）

0.90.0 开发版在 macOS 27.0.1 arm64 通过 **411 项自动化测试（382 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 412 项。日志见 [verification-0.90.0.txt](verification-0.90.0.txt)，逐项清单见 [validation-evidence-0.90.0.json](validation-evidence-0.90.0.json)。

| 检查 | 结果 |
| --- | --- |
| 服务端 | `--tls-client-ca` 校验客户端证书 |
| 客户端 | `--tls-client-cert/--tls-client-key` 提供身份 |
| 测试 | 真实 CA/客户端证书完成 mTLS 并回显 |
| 限制 | 公网监听仍明文；无重放保护 |

## 0.89.0 反向 mux 控制 TLS（历史）

0.89.0 开发版在 macOS 27.0.1 arm64 通过 **410 项自动化测试（381 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 411 项。日志见 [verification-0.89.0.txt](verification-0.89.0.txt)，逐项清单见 [validation-evidence-0.89.0.json](validation-evidence-0.89.0.json)。

| 检查 | 结果 |
| --- | --- |
| 服务端 | cert/key 同时提供才启用 |
| 客户端 | CA + server name 校验 |
| 测试 | TLS 控制连接回显一个公网流 |
| 限制 | 公网监听仍明文；无 mTLS/重放保护 |

## 0.88.0 反向连接超时（历史）

0.88.0 开发版在 macOS 27.0.1 arm64 通过 **409 项自动化测试（380 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 410 项。日志见 [verification-0.88.0.txt](verification-0.88.0.txt)，逐项清单见 [validation-evidence-0.88.0.json](validation-evidence-0.88.0.json)。

| 检查 | 结果 |
| --- | --- |
| 认证 | 首行 10 秒超时关闭 |
| 拨号 | 目标 5 秒超时，回 FAIL/错误 |
| 释放 | 超时后流计数释放 |
| 限制 | 不等于 TLS/重放保护 |

## 0.87.0 规则用量指标（历史）

0.87.0 开发版在 macOS 27.0.1 arm64 通过 **409 项自动化测试（380 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 410 项。日志见 [verification-0.87.0.txt](verification-0.87.0.txt)，逐项清单见 [validation-evidence-0.87.0.json](validation-evidence-0.87.0.json)。

| 检查 | 结果 |
| --- | --- |
| 指标 | `relay_rule_usage{...direction="upload_bytes"} 123` |
| 来源 | 用量账本按节点/规则/租户聚合 |
| 上限 | 5000 条序列 |
| 限制 | 累计值，不是实时每连接计量 |

## 0.86.0 反向 token 常量时间比较（历史）

0.86.0 开发版在 macOS 27.0.1 arm64 通过 **409 项自动化测试（380 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 410 项。日志见 [verification-0.86.0.txt](verification-0.86.0.txt)，逐项清单见 [validation-evidence-0.86.0.json](validation-evidence-0.86.0.json)。

| 检查 | 结果 |
| --- | --- |
| 旧协议 | `REVERSE ` token 常量时间比较 |
| mux | `REVERSE-MUX ` token 常量时间比较 |
| 错误 token | 仍返回 `DENY` |
| 限制 | 静态共享密钥，不等于 TLS/重放保护 |

## 0.85.0 反向 mux 空闲超时（历史）

0.85.0 开发版在 macOS 27.0.1 arm64 通过 **409 项自动化测试（380 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 410 项。日志见 [verification-0.85.0.txt](verification-0.85.0.txt)，逐项清单见 [validation-evidence-0.85.0.json](validation-evidence-0.85.0.json)。

| 检查 | 结果 |
| --- | --- |
| 默认 | 300 秒无数据关闭 |
| 范围 | 1..=86400；0 拒绝 |
| 行为 | 发送 `RESET` 并释放流 |
| 限制 | 仅空闲回收，不改变数据路径 |

## 0.84.0 测试稳定性（历史）

0.84.0 开发版在 macOS 27.0.1 arm64 通过 **408 项自动化测试（379 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 409 项。日志见 [verification-0.84.0.txt](verification-0.84.0.txt)，逐项清单见 [validation-evidence-0.84.0.json](validation-evidence-0.84.0.json)。

| 检查 | 结果 |
| --- | --- |
| 端口分配 | 进程内单调计数 + PID 起点 |
| 多路径端口对 | 额外消费一个候选，避免相邻冲突 |
| 串行 | verify.sh 使用 RUST_TEST_THREADS=1 |
| 限制 | 仅测试稳定性，不改变运行时语义 |

## 0.83.0 反向多路复用流上限（历史）

0.83.0 开发版在 macOS 27.0.1 arm64 通过 **408 项自动化测试（379 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 409 项。日志见 [verification-0.83.0.txt](verification-0.83.0.txt)，逐项清单见 [validation-evidence-0.83.0.json](validation-evidence-0.83.0.json)。

| 检查 | 结果 |
| --- | --- |
| 默认 | 每条控制连接 256 个并发流 |
| 范围 | 1..=1024；0 拒绝 |
| 超限 | 新公网连接立即关闭 |
| 限制 | 仍无按流计量/ACL/TLS |

## 0.82.0 反向多路复用验证（历史）

0.82.0 开发版在 macOS 27.0.1 arm64 通过 **407 项自动化测试（378 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 408 项。日志见 [verification-0.82.0.txt](verification-0.82.0.txt)，逐项清单见 [validation-evidence-0.82.0.json](validation-evidence-0.82.0.json)。

| 检查 | 结果 |
| --- | --- |
| 握手 | `REVERSE-MUX`，错误 token 返回 `DENY` |
| 并发 | 一条控制连接并发两个公网连接 |
| 回显 | alpha/bravo 均正确返回 |
| 限制 | 无计量/ACL/TLS/重放保护 |

## 0.81.0 预算指标验证（历史）

0.81.0 开发版在 macOS 27.0.1 arm64 通过 **405 项自动化测试（376 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 406 项。日志见 [verification-0.81.0.txt](verification-0.81.0.txt)，逐项清单见 [validation-evidence-0.81.0.json](validation-evidence-0.81.0.json)。

| 检查 | 结果 |
| --- | --- |
| 指标 | `relay_budget{...kind="limit_bytes"} 10000` |
| 标签 | budget/tenant/scope/scope_id |
| 限制 | 只读，不含预留/租约明细 |

## 0.80.0 目标健康门控验证（历史）

0.80.0 开发版在 macOS 27.0.1 arm64 通过 **405 项自动化测试（376 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 406 项。日志见 [verification-0.80.0.txt](verification-0.80.0.txt)，逐项清单见 [validation-evidence-0.80.0.json](validation-evidence-0.80.0.json)。

| 检查 | 结果 |
| --- | --- |
| 门控 | 每批节点 target_health 非空且全部 eligible |
| 超时 | 默认 5 秒或 wait_for_apply_ms，超时 aborted + gate_error |
| 默认 | 关闭 |
| 限制 | 只看最近探测 eligible，不等于真实流量健康 |

## 0.79.0 恢复日志指标验证（历史）

0.79.0 开发版在 macOS 27.0.1 arm64 通过 **404 项自动化测试（375 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 405 项。日志见 [verification-0.79.0.txt](verification-0.79.0.txt)，逐项清单见 [validation-evidence-0.79.0.json](validation-evidence-0.79.0.json)。

| 检查 | 结果 |
| --- | --- |
| enabled | 1 |
| healthy | 1 |
| head | sequence/committed_bytes（存在 head 时） |
| 限制 | 本机日志状态，不代表异地备份 |

## 0.78.0 计量/额度指标验证（历史）

0.78.0 开发版在 macOS 27.0.1 arm64 通过 **404 项自动化测试（375 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 405 项。日志见 [verification-0.78.0.txt](verification-0.78.0.txt)，逐项清单见 [validation-evidence-0.78.0.json](validation-evidence-0.78.0.json)。

| 检查 | 结果 |
| --- | --- |
| 计量 | admission_requests=3 |
| 额度恢复 | validated_grants=2 |
| 限制 | 节点级聚合，无租户/规则维度 |

## 0.77.0 24 小时遥测窗口（历史）

0.77.0 开发版在 macOS 27.0.1 arm64 通过 **404 项自动化测试（375 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 405 项。日志见 [verification-0.77.0.txt](verification-0.77.0.txt)，逐项清单见 [validation-evidence-0.77.0.json](validation-evidence-0.77.0.json)。

| 检查 | 结果 |
| --- | --- |
| 窗口 | WINDOW_MS 24 小时，每节点最多 20000 采样 |
| 文案 | 总览页显示最近 24 小时 |
| 边界 | 控制器重启仍从空历史开始，事件上限 500 |
| 限制 | 内存历史，不是持久化时序库 |

## 0.76.0 系统资源指标验证（历史）

0.76.0 开发版在 macOS 27.0.1 arm64 通过 **404 项自动化测试（375 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 405 项。日志见 [verification-0.76.0.txt](verification-0.76.0.txt)，逐项清单见 [validation-evidence-0.76.0.json](validation-evidence-0.76.0.json)。

| 检查 | 结果 |
| --- | --- |
| CPU | `relay_node_system{kind="cpu_percent"} 12.5` |
| 内存/RSS/负载 | 有值时输出，无值省略 |
| 限制 | 节点级采样，无直方图/长期历史 |

## 0.75.0 多路径指标验证（历史）

0.75.0 开发版在 macOS 27.0.1 arm64 通过 **404 项自动化测试（375 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 405 项。日志见 [verification-0.75.0.txt](verification-0.75.0.txt)，逐项清单见 [validation-evidence-0.75.0.json](validation-evidence-0.75.0.json)。

| 检查 | 结果 |
| --- | --- |
| 会话/路径 | active_sessions=1、active_paths=2 |
| 负载 | delivered=4096，按 kind 输出 |
| 失败路径 | 输出 failed_paths |
| 限制 | 进程级计数，无每会话/路径标签 |

## 0.74.0 映射恢复与 CLI runtime 修复（历史）

0.74.0 开发版在 macOS 27.0.1 arm64 通过 **404 项自动化测试（375 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 405 项。日志见 [verification-0.74.0.txt](verification-0.74.0.txt)，逐项清单见 [validation-evidence-0.74.0.json](validation-evidence-0.74.0.json)。

| 检查 | 结果 |
| --- | --- |
| 旧映射 | 先删除状态文件中的旧外部端口 40000 |
| 新映射 | 再创建 40001 并写回状态 |
| CLI | 真实子进程退出码 0，无嵌套 runtime panic |
| 限制 | 需显式 `--restore-state`，无真实路由器验收 |

## 0.73.0 目标健康指标验证（历史）

0.73.0 开发版在 macOS 27.0.1 arm64 通过 **403 项自动化测试（374 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 404 项。日志见 [verification-0.73.0.txt](verification-0.73.0.txt)，逐项清单见 [validation-evidence-0.73.0.json](validation-evidence-0.73.0.json)。

| 检查 | 结果 |
| --- | --- |
| 资格 | eligible + status 标签 |
| 延迟 | latency_ewma_us=1500 |
| 其他 | 窗口失败、活动会话、探测总数 |
| 限制 | 无直方图/长期历史；行数随目标数增长 |

## 0.72.0 配置同步指标验证（历史）

0.72.0 开发版在 macOS 27.0.1 arm64 通过 **403 项自动化测试（374 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 404 项。日志见 [verification-0.72.0.txt](verification-0.72.0.txt)，逐项清单见 [validation-evidence-0.72.0.json](validation-evidence-0.72.0.json)。

| 检查 | 结果 |
| --- | --- |
| 修订 | applied=0、desired=0 |
| 同步 | config_in_sync=1 |
| 最后同步 | 从未同步时不输出时间戳 |
| 限制 | 无规则级/目标健康直方图或长期历史 |

## 0.71.0 扩展指标验证（历史）

0.71.0 开发版在 macOS 27.0.1 arm64 通过 **403 项自动化测试（374 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 404 项。日志见 [verification-0.71.0.txt](verification-0.71.0.txt)，逐项清单见 [validation-evidence-0.71.0.json](validation-evidence-0.71.0.json)。

| 检查 | 结果 |
| --- | --- |
| 活动 UDP | 输出节点活动 UDP 会话 |
| 接纳 | 输出 accepted TCP 计数 |
| 其他 | 拒绝/失败/丢弃/预热计数 |
| 限制 | 无规则级/目标健康直方图或长期历史 |

## 0.70.0 Prometheus 指标验证（历史）

0.70.0 开发版在 macOS 27.0.1 arm64 通过 **403 项自动化测试（374 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 404 项。日志见 [verification-0.70.0.txt](verification-0.70.0.txt)，逐项清单见 [validation-evidence-0.70.0.json](validation-evidence-0.70.0.json)。

| 检查 | 结果 |
| --- | --- |
| 认证 | Viewer 登录后可读 |
| 内容 | 构建信息、节点在线、活动 TCP、转发字节 |
| 格式 | `text/plain; version=0.0.4` |
| 限制 | 无规则级/UDP/延迟直方图或长期历史 |

## 0.69.0 DNS 分页验证（历史）

0.69.0 开发版在 macOS 27.0.1 arm64 通过 **402 项自动化测试（373 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 403 项。日志见 [verification-0.69.0.txt](verification-0.69.0.txt)，逐项清单见 [validation-evidence-0.69.0.json](validation-evidence-0.69.0.json)。

| 检查 | 结果 |
| --- | --- |
| 分页 | 两页结果按顺序合并为 2 条 |
| 上限 | 每页 100、最多 50 页 |
| 兼容 | 无 result_info 时单页 |
| 限制 | 未做真实 Cloudflare/传播/端到端验收 |

## 0.68.0 应用回执门控验证（历史）

0.68.0 开发版在 macOS 27.0.1 arm64 通过 **401 项自动化测试（372 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 402 项。日志见 [verification-0.68.0.txt](verification-0.68.0.txt)，逐项清单见 [validation-evidence-0.68.0.json](validation-evidence-0.68.0.json)。

| 检查 | 结果 |
| --- | --- |
| 超时 | 无 applied 回执时 100ms 后 aborted |
| 已写入 | 配置 revision 已生成，applied=1 |
| 错误 | `gate_error` 指出节点未在时限内应用 |
| 限制 | 只验证配置应用回执，不验证流量/错误率/延迟 |

## 0.67.0 批量健康预检验证（历史）

0.67.0 开发版在 macOS 27.0.1 arm64 通过 **400 项自动化测试（371 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 401 项。日志见 [verification-0.67.0.txt](verification-0.67.0.txt)，逐项清单见 [validation-evidence-0.67.0.json](validation-evidence-0.67.0.json)。

| 检查 | 结果 |
| --- | --- |
| 未同步 | 90 秒内无同步的节点被拒绝，未写配置 |
| 应用错误 | 有 `apply_error` 的节点被拒绝 |
| 关闭预检 | 同一节点可正常应用 |
| 限制 | 预检不是应用后健康观察或自动放量 |

## 0.66.0 指数退避重试验证（历史）

0.66.0 开发版在 macOS 27.0.1 arm64 通过 **399 项自动化测试（370 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 400 项。日志见 [verification-0.66.0.txt](verification-0.66.0.txt)，逐项清单见 [validation-evidence-0.66.0.json](validation-evidence-0.66.0.json)。

| 检查 | 结果 |
| --- | --- |
| 翻倍 | 50ms → 100ms |
| 封顶 | 下一轮 150ms 不超过 max |
| 边界 | 零初始/上限小于初始拒绝；成功后回到初始 |
| 限制 | 仍无自动映射恢复/清理 |

## 0.65.0 映射状态文件验证（历史）

0.65.0 开发版在 macOS 27.0.1 arm64 通过 **398 项自动化测试（369 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 399 项。日志见 [verification-0.65.0.txt](verification-0.65.0.txt)，逐项清单见 [validation-evidence-0.65.0.json](validation-evidence-0.65.0.json)。

| 检查 | 结果 |
| --- | --- |
| 原子写 | 嵌套目录写入后无临时文件 |
| 重载 | JSON 映射字段一致 |
| 删除 | 幂等删除，缺失文件不报错 |
| 损坏 | 非 JSON 内容报错 |
| 限制 | 不自动恢复映射；仅最后状态 |

## 0.64.0 UPnP 事件属性验证（历史）

0.64.0 开发版在 macOS 27.0.1 arm64 通过 **396 项自动化测试（367 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 397 项。日志见 [verification-0.64.0.txt](verification-0.64.0.txt)，逐项清单见 [validation-evidence-0.64.0.json](validation-evidence-0.64.0.json)。

| 检查 | 结果 |
| --- | --- |
| 提取 | ExternalIPAddress、PortMappingNumberOfEntries 按叶级元素提取 |
| 命名空间 | 去掉前缀后按键输出 |
| 边界 | 空属性集为空；最多 64 项/4096 字节 |
| 限制 | 不执行 XML/实体，不做嵌套语义或事件动作分发 |

## 0.63.0 UPnP 事件回调验证（历史）

0.63.0 开发版在 macOS 27.0.1 arm64 通过 **395 项自动化测试（366 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 396 项。日志见 [verification-0.63.0.txt](verification-0.63.0.txt)，逐项清单见 [validation-evidence-0.63.0.json](validation-evidence-0.63.0.json)。

| 检查 | 结果 |
| --- | --- |
| 回调 | 本地 HTTP 接收 NOTIFY，提取 SID/SEQ 与原始正文 |
| 生命周期 | 订阅、半超时续订、取消后退订 |
| 边界 | 仅明文 IPv4/localhost；不解析属性 |
| 限制 | 无事件动作分发、TLS 回调、完整 IGD 筛选或状态持久化 |

## 0.62.0 NAT 重试验证（历史）

0.62.0 开发版在 macOS 27.0.1 arm64 通过 **394 项自动化测试（365 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 395 项。日志见 [verification-0.62.0.txt](verification-0.62.0.txt)，逐项清单见 [validation-evidence-0.62.0.json](validation-evidence-0.62.0.json)。

| 检查 | 结果 |
| --- | --- |
| 重试 | 假网关首次拒绝、第二次成功；`--retry-secs` 后 epoch 生效 |
| 边界 | 省略重试则失败退出；零间隔拒绝 |
| 限制 | 固定间隔，无指数退避/状态持久化/真实路由器验收 |

## 0.61.0 目的地端口 ACL 验证（历史）

0.61.0 开发版在 macOS 27.0.1 arm64 通过 **393 项自动化测试（364 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 394 项。日志见 [verification-0.61.0.txt](verification-0.61.0.txt)，逐项清单见 [validation-evidence-0.61.0.json](validation-evidence-0.61.0.json)。

| 检查 | 结果 |
| --- | --- |
| 单端口/范围 | 443、8000-8080 放行；80 拒绝 |
| 拒绝优先 | 8443、9000-9001 拒绝 |
| 边界 | 反向范围拒绝；端口与主机/IP 同时满足 |
| 限制 | 无 GeoIP/ASN、协议组合、多规则链或真实域名污染测试 |

## 0.60.0 UPnP 事件订阅验证（历史）

0.60.0 开发版在 macOS 27.0.1 arm64 通过 **392 项自动化测试（363 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 393 项。日志见 [verification-0.60.0.txt](verification-0.60.0.txt)，逐项清单见 [validation-evidence-0.60.0.json](validation-evidence-0.60.0.json)。

| 检查 | 结果 |
| --- | --- |
| 订阅 | SUBSCRIBE 携带 CALLBACK/NT/TIMEOUT，返回 SID/超时 |
| 续订/退订 | 使用 SID 续订和 UNSUBSCRIBE |
| 限制 | 不解析事件正文、不提供回调服务；无完整 IGD 筛选/状态持久化 |

## 0.59.0 百分比首批验证（历史）

0.59.0 开发版在 macOS 27.0.1 arm64 通过 **391 项自动化测试（362 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 392 项。日志见 [verification-0.59.0.txt](verification-0.59.0.txt)，逐项清单见 [validation-evidence-0.59.0.json](validation-evidence-0.59.0.json)。

| 检查 | 结果 |
| --- | --- |
| 首批 | 3 节点、batch=2、34% → 首批 2，第二批 1 |
| 上限 | 首批比例计算不超过 batch_size，至少 1 |
| 失败 | 原有停止/回滚/重试语义不变 |
| 限制 | 仅批次大小；无观察窗口/错误率/延迟健康阈值 |

## 0.58.0 模板 diff 验证（历史）

0.58.0 开发版在 macOS 27.0.1 arm64 通过 **390 项自动化测试（361 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 391 项。日志见 [verification-0.58.0.txt](verification-0.58.0.txt)，逐项清单见 [validation-evidence-0.58.0.json](validation-evidence-0.58.0.json)。

| 检查 | 结果 |
| --- | --- |
| 路径 | v1→v2 差异包含 `/rule/targets/0/address` |
| 范围 | 名称、描述、规则、变量；数组按索引；最多 512 项 |
| 限制 | 结构化 JSON 比较，不是语义/格式化 diff；无百分比 canary |

## 0.57.0 反向会话池验证（历史）

0.57.0 开发版在 macOS 27.0.1 arm64 通过 **390 项自动化测试（361 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 391 项。日志见 [verification-0.57.0.txt](verification-0.57.0.txt)，逐项清单见 [validation-evidence-0.57.0.json](validation-evidence-0.57.0.json)。

| 检查 | 结果 |
| --- | --- |
| 并发 | `--sessions 2` 时两个公网连接同时回显 |
| 顺序 | 原有两顺序连接仍通过 |
| 认证 | 错误 token 仍 DENY |
| 限制 | 每条控制连接仍单会话；无 mux/计量/ACL/TLS/WireGuard |

## 0.56.0 固定版本应用验证（历史）

0.56.0 开发版在 macOS 27.0.1 arm64 通过 **389 项自动化测试（360 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 390 项。日志见 [verification-0.56.0.txt](verification-0.56.0.txt)，逐项清单见 [validation-evidence-0.56.0.json](validation-evidence-0.56.0.json)。

| 检查 | 结果 |
| --- | --- |
| 固定版本 | v2 后应用 `template_version=1`，使用 v1 的目标 |
| 默认 | 省略版本使用当前最新内容 |
| 复用 | 批量目标可携带版本；重试保留 |
| 限制 | 只固定模板内容，不恢复节点配置；无 diff/百分比 canary |

## 0.55.0 模板版本验证（历史）

0.55.0 开发版在 macOS 27.0.1 arm64 通过 **389 项自动化测试（360 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 390 项。日志见 [verification-0.55.0.txt](verification-0.55.0.txt)，逐项清单见 [validation-evidence-0.55.0.json](validation-evidence-0.55.0.json)。

| 检查 | 结果 |
| --- | --- |
| 历史 | v1 创建、v2 更新；版本列表 2 项 |
| 回滚 | 回滚 v1 生成 v3，名称/目标恢复，版本列表 3 项 |
| 审计 | 回滚写审计；只允许严格更旧版本 |
| 限制 | 应用仍用最新版本；无固定版本发布、完整 diff、百分比 canary |

## 0.54.0 模板变量验证（历史）

0.54.0 开发版在 macOS 27.0.1 arm64 通过 **388 项自动化测试（359 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 389 项。日志见 [verification-0.54.0.txt](verification-0.54.0.txt)，逐项清单见 [validation-evidence-0.54.0.json](validation-evidence-0.54.0.json)。

| 检查 | 结果 |
| --- | --- |
| 默认变量 | `{{host}}:9000` 渲染为 `127.0.0.1:9000` |
| 覆盖 | apply-time `host=localhost` 渲染为 `localhost:9000` |
| 校验 | 创建/更新时完整规则校验；缺失变量拒绝 |
| 限制 | 仅字符串替换；无表达式、条件、密钥引用、版本化或百分比 canary |

## 0.53.0 反向隧道验证（历史）

0.53.0 开发版在 macOS 27.0.1 arm64 通过 **387 项自动化测试（358 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 388 项。日志见 [verification-0.53.0.txt](verification-0.53.0.txt)，逐项清单见 [validation-evidence-0.53.0.json](validation-evidence-0.53.0.json)。

| 检查 | 结果 |
| --- | --- |
| 认证 | 错误 token 收到 DENY |
| 转发 | 两个顺序公网连接均回显，客户端会话结束后重连 |
| 边界 | 单会话、顺序服务；控制行 ≤512，token 1..256 |
| 限制 | 无多路复用/并发、计量、ACL、TLS、重放保护或 WireGuard |

## 0.52.0 SSDP 发现验证（历史）

0.52.0 开发版在 macOS 27.0.1 arm64 通过 **385 项自动化测试（356 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 386 项。日志见 [verification-0.52.0.txt](verification-0.52.0.txt)，逐项清单见 [validation-evidence-0.52.0.json](validation-evidence-0.52.0.json)。

| 检查 | 结果 |
| --- | --- |
| SSDP | 假服务收到 M-SEARCH，返回两个相同 LOCATION，结果去重为 1 |
| 字段 | 解析 LOCATION、SERVER、ST、USN |
| 范围 | 仅 IPv4；不解析设备 XML、不自动选网关 |
| 限制 | 无完整 IGD 服务筛选、事件订阅、状态持久化、失败退避或真实路由器验收 |

## 0.51.0 PCP/UPnP 续租验证（历史）

0.51.0 开发版在 macOS 27.0.1 arm64 通过 **384 项自动化测试（355 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 385 项。日志见 [verification-0.51.0.txt](verification-0.51.0.txt)，逐项清单见 [validation-evidence-0.51.0.json](validation-evidence-0.51.0.json)。

| 检查 | 结果 |
| --- | --- |
| PCP | 假网关连续两次请求，epoch 1/2，取消后退出 |
| UPnP | 假 HTTP 服务连续两次 AddPortMapping，取消后退出 |
| 边界 | 间隔必须小于生命周期；`--delete` 不续租 |
| 限制 | 仅续租；SSDP、事件订阅、状态持久化、失败退避、真实路由器未验收 |

## 0.50.0 NAT-PMP 续租验证（历史）

0.50.0 开发版在 macOS 27.0.1 arm64 通过 **382 项自动化测试（353 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 383 项。日志见 [verification-0.50.0.txt](verification-0.50.0.txt)，逐项清单见 [validation-evidence-0.50.0.json](validation-evidence-0.50.0.json)。

| 检查 | 结果 |
| --- | --- |
| 续租 | 假网关连续两次请求，epoch 1/2，外部端口保持 |
| 取消 | 两次回调后取消，任务及时退出 |
| 边界 | 续租间隔必须小于生命周期；`--delete` 不续租 |
| 限制 | 仅 NAT-PMP；PCP/UPnP 续租、状态持久化、真实路由器未验收 |

## 0.49.0 rollout 重试验证（历史）

0.49.0 开发版在 macOS 27.0.1 arm64 通过 **381 项自动化测试（352 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 382 项。日志见 [verification-0.49.0.txt](verification-0.49.0.txt)，逐项清单见 [validation-evidence-0.49.0.json](validation-evidence-0.49.0.json)。

| 检查 | 结果 |
| --- | --- |
| 持久化 | rollout 结果写入 metadata，保留目标/批次/回滚/结果 |
| 重试 | 只选失败/未尝试节点；按当前修订重新应用；成功节点不重复 |
| 测试 | 首批 a 成功、b 失败、c 未尝试；重试 b/c 均成功 |
| 限制 | 不重放旧快照；无变量/百分比健康阈值/依赖图/浏览器点击 |

## 0.48.0 模板 canary 回滚验证（历史）

0.48.0 开发版在 macOS 27.0.1 arm64 通过 **381 项自动化测试（352 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 382 项。日志见 [verification-0.48.0.txt](verification-0.48.0.txt)，逐项清单见 [validation-evidence-0.48.0.json](validation-evidence-0.48.0.json)。

| 检查 | 结果 |
| --- | --- |
| 回滚 | 3 节点、batch=1、失败批次后成功节点规则被移除，`rolled_back=1` |
| 顺序 | 按成功应用反序移除；使用应用后修订，冲突回滚会显式失败 |
| 限制 | 只移除本次新建规则，不恢复旧配置快照；无百分比/健康阈值/浏览器点击验收 |

## 0.47.0 模板 canary 验证（历史）

0.47.0 开发版在 macOS 27.0.1 arm64 通过 **381 项自动化测试（352 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 382 项。日志见 [verification-0.47.0.txt](verification-0.47.0.txt)，逐项清单见 [validation-evidence-0.47.0.json](validation-evidence-0.47.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 3 节点、batch=1；首批成功、第二批失败后停止，第三节点标记未尝试 |
| 身份 | 每节点独立 expected_revision、新规则 ID/监听/owner/tenant/meter |
| 面板 | `node --check`、编辑器/视图结构；批量 JSON 源码流程 |
| 限制 | 无自动回滚、变量、百分比/健康阈值、依赖图或浏览器点击验收 |

## 0.46.0 审查 R1–R5 验证（历史）

0.46.0 稳定化版在 macOS 27.0.1 arm64 通过 **380 项自动化测试（351 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 381 项。日志见 [verification-0.46.0.txt](verification-0.46.0.txt)，逐项清单见 [validation-evidence-0.46.0.json](validation-evidence-0.46.0.json)。

| 检查 | 结果 |
| --- | --- |
| R1 | 同 IP 两个 UDP 关联获得不同中继端点；A/B 各自回显，互不串流 |
| R2 | 混合 A/AAAA 只保留允许地址；审查 DNS 探针不再复现 |
| R3 | 错误/被拒绝 BIND 对端被丢弃并返回失败 |
| R4 | 控制关闭 1.3 秒后不再收到回复；关联任务取消 |
| R5 | 失败修订下新 1 KiB/s 限额在 16 秒内生效，128 KiB 回显被限速 |
| 审查探针 | 修复后 5 项均 `defect_reproduced=false` |

## 0.45.0 SOCKS5 BIND 验证（历史）

0.45.0 开发版在 macOS 27.0.1 arm64 通过 **375 项自动化测试（346 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 376 项。日志见 [verification-0.45.0.txt](verification-0.45.0.txt)，逐项清单见 [validation-evidence-0.45.0.json](validation-evidence-0.45.0.json)。

| 检查 | 结果 |
| --- | --- |
| 集成 | TCP 控制握手、BIND 两次回复、入站 TCP 连接、双向 12 字节回显 |
| 规则 | 零端口仅 BIND/UDP 允许，CONNECT 仍拒绝 |
| 限制 | 入站来源未套用规则 ACL/限速；无真实 FTP/客户端矩阵 |

## 0.44.0 UPnP 验证（历史）

0.44.0 开发版在 macOS 27.0.1 arm64 通过 **374 项自动化测试（345 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 375 项。日志见 [verification-0.44.0.txt](verification-0.44.0.txt)，逐项清单见 [validation-evidence-0.44.0.json](validation-evidence-0.44.0.json)。

| 检查 | 结果 |
| --- | --- |
| 解析 | WANIPConnection/WANPPPConnection、相对 controlURL、缺失/空 controlURL 失败 |
| SOAP | AddPortMapping/DeletePortMapping 字段、control URL、HTTP 成功 |
| 限制 | 无 SSDP/事件订阅、续租/重试、IPv6 完整矩阵、反向隧道、WireGuard |

## 0.43.0 PCP 验证（历史）

0.43.0 开发版在 macOS 27.0.1 arm64 通过 **372 项自动化测试（343 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 373 项。日志见 [verification-0.43.0.txt](verification-0.43.0.txt)，逐项清单见 [validation-evidence-0.43.0.json](validation-evidence-0.43.0.json)。

| 检查 | 结果 |
| --- | --- |
| 集成 | 假网关验证 60 字节请求、nonce、成功映射、IPv4-mapped 外部地址、删除 |
| 单元 | 版本/拒绝/短响应、非法 gateway 失败 |
| 限制 | 无 UPnP、续租/重试、固定源端口、IPv6 完整矩阵、反向隧道、WireGuard |

## 0.42.0 NAT-PMP 验证（历史）

0.42.0 开发版在 macOS 27.0.1 arm64 通过 **370 项自动化测试（341 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 371 项。日志见 [verification-0.42.0.txt](verification-0.42.0.txt)，逐项清单见 [validation-evidence-0.42.0.json](validation-evidence-0.42.0.json)。

| 检查 | 结果 |
| --- | --- |
| 集成 | 假网关验证请求字段、成功映射、epoch/外部端口、删除请求 |
| 单元 | 非法 gateway、IPv6 拒绝、短/拒绝响应失败 |
| 限制 | 无 PCP/UPnP、续租/重试、IPv6、反向隧道、WireGuard 或真实路由器 |

## 0.41.0 模板预览验证（历史）

0.41.0 开发版在 macOS 27.0.1 arm64 通过 **368 项自动化测试（339 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 369 项。日志见 [verification-0.41.0.txt](verification-0.41.0.txt)，逐项清单见 [validation-evidence-0.41.0.json](validation-evidence-0.41.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 预览不改变修订、拟创建身份正确、重复监听 `valid=false` |
| HTTP | 预览返回 `valid/current_revision`，viewer 写权限仍拒绝 |
| 限制 | 无模板版本化/完整差异/变量/灰度/依赖图/浏览器点击验收 |

## 0.40.0 MPTCP 能力观测验证（历史）

0.40.0 开发版在 macOS 27.0.1 arm64 通过 **368 项自动化测试（339 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 369 项。日志见 [verification-0.40.0.txt](verification-0.40.0.txt)，逐项清单见 [validation-evidence-0.40.0.json](validation-evidence-0.40.0.json)。

| 检查 | 结果 |
| --- | --- |
| 单元 | 平台字段、note、非 Linux 明确 unsupported；路由/端点上限 |
| HTTP | 管理员读取 `supported/note`，viewer 403 |
| 边界 | 只读观测，不修改规则/监听/转发；`active_connections=null` |

## 0.39.0 SOCKS5 UDP 性能验证（历史）

0.39.0 开发版在 macOS 27.0.1 arm64 通过 **367 项自动化测试（338 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 368 项。日志见 [verification-0.39.0.txt](verification-0.39.0.txt)，逐项清单见 [validation-evidence-0.39.0.json](validation-evidence-0.39.0.json)。

| 检查 | 结果 |
| --- | --- |
| 基准 | 1000 × 1200 B、32 窗口、零丢失；RTT 与 goodput 见 [PERFORMANCE.md](PERFORMANCE.md) |
| 路径 | TCP 控制 + UDP ASSOCIATE + 真实回显；逐个校验载荷 |
| 限制 | loopback/Python 回显，无 WAN/TLS/真实客户端/CPU/RSS/SLA |

## 0.38.0 规则模板验证（历史）

0.38.0 开发版在 macOS 27.0.1 arm64 通过 **367 项自动化测试（338 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 368 项。日志见 [verification-0.38.0.txt](verification-0.38.0.txt)，逐项清单见 [validation-evidence-0.38.0.json](validation-evidence-0.38.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 创建/列表、应用生成新 ID/名称/监听/owner/tenant/meter、旧修订 409、viewer 403 |
| HTTP | 创建、viewer 403、节点配置修订、应用后规则名称 |
| 面板 | `node --check`、编辑器序列化与视图结构；模板页源码，未做浏览器点击验收 |

## 0.37.0 SOCKS5 UDP 计量验证（历史）

0.37.0 开发版在 macOS 27.0.1 arm64 通过 **365 项自动化测试（336 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 366 项。日志见 [verification-0.37.0.txt](verification-0.37.0.txt)，逐项清单见 [validation-evidence-0.37.0.json](validation-evidence-0.37.0.json)。

| 检查 | 结果 |
| --- | --- |
| Engine | 16 个连续 UDP 数据报复用出口 socket、全部回显 |
| 计量 | 载荷上传/下载计入规则计量并受限速；头部不计；不足时丢弃 |
| 限制 | 未做 UDP 吞吐报告、背压、分片、真实客户端矩阵 |

## 0.36.0 SOCKS5 UDP socket 复用验证（历史）

0.36.0 开发版在 macOS 27.0.1 arm64 通过 **365 项自动化测试（336 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 366 项。日志见 [verification-0.36.0.txt](verification-0.36.0.txt)，逐项清单见 [validation-evidence-0.36.0.json](validation-evidence-0.36.0.json)。

| 检查 | 结果 |
| --- | --- |
| Engine | 真实 TCP 控制 + UDP ASSOCIATE；连续 16 个数据报全部回显 |
| 复用 | 每个关联共享 IPv4 出口 socket 和响应任务，取消时清理 |
| 安全 | 目的地 ACL、私网策略、出口绑定、来源地址包装仍生效 |
| 限制 | 未按目标复用/背压、无分片、真实客户端矩阵或正式吞吐报告 |

## 0.35.0 SOCKS5 UDP ASSOCIATE 验证（历史）

0.35.0 开发版在 macOS 27.0.1 arm64 通过 **365 项自动化测试（336 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 366 项。日志见 [verification-0.35.0.txt](verification-0.35.0.txt)，逐项清单见 [validation-evidence-0.35.0.json](validation-evidence-0.35.0.json)。

| 检查 | 结果 |
| --- | --- |
| 协议 | TCP 控制握手、UDP ASSOCIATE、绑定地址回复、UDP 头解析/编码 |
| Engine | 真实 TCP 控制 + UDP 回显目标；ACL/私网、来源地址包装、控制关闭清理 |
| 规则 | `protocol=both`、单端口、TCP-only 拒绝/端口段拒绝 |
| 性能 | 当前每数据报独立出口 socket，未做吞吐优化或真实客户端矩阵 |

## 0.34.0 目的地 ACL 验证（历史）

0.34.0 开发版在 macOS 27.0.1 arm64 通过 **364 项自动化测试（335 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 365 项。日志见 [verification-0.34.0.txt](verification-0.34.0.txt)，逐项清单见 [validation-evidence-0.34.0.json](validation-evidence-0.34.0.json)。

| 检查 | 结果 |
| --- | --- |
| 单元 | 后缀/精确域名、CIDR/IP、拒绝优先、空允许为全通、非法模式拒绝 |
| Engine | 拒绝目的地时目标 listener 零连接；允许 CIDR 时真实 TCP 回显 |
| 面板 | `node --check web/app.js`、编辑器序列化与视图结构检查；未做浏览器点击验收 |

## 0.33.0 性能验证（历史）

0.33.0 开发版在 macOS 27.0.1 arm64 通过 **360 项自动化测试（331 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 361 项。日志见 [verification-0.33.0.txt](verification-0.33.0.txt)，逐项清单见 [validation-evidence-0.33.0.json](validation-evidence-0.33.0.json)。

| 检查 | 结果 |
| --- | --- |
| 并发矩阵 | 1/8/32 连接、每连接 8 MiB、3 轮；直连与 Relay 交替 |
| 吞吐 | Relay/直连约 0.504（1）、0.909（8）、0.945（32） |
| 延迟 | Relay p95 连接耗时 12.9/52.1/235.0 ms；UDP p95 RTT 165.4 µs |
| 正确性 | 双向逐字节校验通过；账本 2,066,174,720 字节精确匹配 |
| 限制 | 本机 loopback、无 TLS/WAN/真实客户端、无 CPU/RSS/72 小时/竞品对照 |

## 0.32.0 HTTP CONNECT 验证（历史）

0.32.0 开发版在 macOS 27.0.1 arm64 通过 **360 项自动化测试（331 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 361 项。日志见 [verification-0.32.0.txt](verification-0.32.0.txt)，逐项清单见 [validation-evidence-0.32.0.json](validation-evidence-0.32.0.json)。

| 检查 | 结果 |
| --- | --- |
| 协议单元 | 域名 CONNECT、成功响应、Basic 认证、缺失认证 407、成功路径 |
| Engine | 真实监听、CONNECT 到 TCP 回显目标、200 响应与双向字节转发 |
| 规则校验 | TCP-only、无固定目标、认证成对、与 SOCKS5 互斥 |
| 面板 | `node --check web/app.js` 与视图结构检查；HTTP CONNECT 编辑器/分享源码，未做浏览器点击验收 |

## 0.31.0 礼品码验证（历史）

0.31.0 开发版在 macOS 27.0.1 arm64 通过 **355 项自动化测试（326 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 356 项。日志见 [verification-0.31.0.txt](verification-0.31.0.txt)，逐项清单见 [validation-evidence-0.31.0.json](validation-evidence-0.31.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 管理员创建、非管理员 403、兑换入账、每用户一次、次数上限、停用/过期、删除已兑换 409 |
| HTTP | 管理员创建、买家 403、兑换入钱包、重复兑换 409、删除已兑换 409 |
| 面板 | `node --check web/app.js` 与视图结构检查；礼品码/兑换源码，未做浏览器点击验收 |

## 0.30.0 优惠码验证（历史）

0.30.0 开发版在 macOS 27.0.1 arm64 通过 **353 项自动化测试（324 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 354 项。日志见 [verification-0.30.0.txt](verification-0.30.0.txt)，逐项清单见 [validation-evidence-0.30.0.json](validation-evidence-0.30.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 10% 折扣、原价/折扣/最终金额、使用次数上限、停用拒绝、折后支付/退款 |
| HTTP | 管理员创建优惠码、买家 403、订单折扣字段、折后钱包支付与退款 |
| 面板 | `node --check web/app.js` 与视图结构检查；优惠码管理源码，未做浏览器点击验收 |

## 0.29.0 工单验证（历史）

0.29.0 开发版在 macOS 27.0.1 arm64 通过 **352 项自动化测试（323 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 353 项。日志见 [verification-0.29.0.txt](verification-0.29.0.txt)，逐项清单见 [validation-evidence-0.29.0.json](validation-evidence-0.29.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 所有者/其他用户/租户管理员/其他租户/系统管理员作用域、内部备注隔离、关闭权限、关闭后回复 409、重开 |
| HTTP | 创建、其他用户 403、管理员内部备注、所有者只看到公开消息、关闭/关闭后 409 |
| 面板 | `node --check web/app.js` 与视图结构检查；工单页源码，未做浏览器点击验收 |

## 0.28.0 外部支付回调验证（历史）

0.28.0 开发版在 macOS 27.0.1 arm64 通过 **350 项自动化测试（321 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 351 项。日志见 [verification-0.28.0.txt](verification-0.28.0.txt)，逐项清单见 [validation-evidence-0.28.0.json](validation-evidence-0.28.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store/HTTP | HMAC 签名失败 401、支付成功、重复回调幂等、订单外部通道、钱包余额不变、外部订单钱包退款 409 |
| 面板 | `node --check web/app.js` 与视图结构检查；外部支付/回调密钥源码，未做浏览器点击验收 |

## 0.27.0 套餐、钱包与订单验证（历史）

0.27.0 开发版在 macOS 27.0.1 arm64 通过 **349 项自动化测试（320 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 350 项。日志见 [verification-0.27.0.txt](verification-0.27.0.txt)，逐项清单见 [validation-evidence-0.27.0.json](validation-evidence-0.27.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 套餐启停可见性、非管理员 403、钱包入账/重复引用 409/负余额拒绝、订单快照、支付扣款、重复支付/退款 409、用户退款 403、余额与流水 |
| HTTP | 创建套餐、买家 403 建套餐、管理员调钱包、买家建单/支付、余额、管理员退款、最终余额 |
| 面板 | `node --check web/app.js` 与视图结构检查；钱包/订单页源码，未做浏览器点击验收 |

## 0.26.0 公告验证（历史）

0.26.0 开发版在 macOS 27.0.1 arm64 通过 **347 项自动化测试（318 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 348 项。日志见 [verification-0.26.0.txt](verification-0.26.0.txt)，逐项清单见 [validation-evidence-0.26.0.json](validation-evidence-0.26.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 全局/租户可见性、其他租户隔离、未来公告隐藏、租户管理员全局只读/本租户可写、删除 |
| HTTP | 管理员发布、普通用户读取、普通用户写 403、管理列表 403、删除 |
| 面板 | `node --check web/app.js` 与视图结构检查；公告页源码，未做浏览器点击验收 |

## 0.25.0 SOCKS5 入口验证（历史）

0.25.0 开发版在 macOS 27.0.1 arm64 通过 **345 项自动化测试（316 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器/视图结构回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 346 项。日志见 [verification-0.25.0.txt](verification-0.25.0.txt)，逐项清单见 [validation-evidence-0.25.0.json](validation-evidence-0.25.0.json)。

| 检查 | 结果 |
| --- | --- |
| 协议单元 | 4 项：无认证域名 CONNECT、成功回复编码、用户名/密码、错误密码、UDP ASSOCIATE 拒绝 |
| 规则校验 | TCP-only、无固定目标、认证成对、SOCKS5/Shadowsocks 互斥 |
| Engine | 真实监听、CONNECT 到 TCP 回显目标、状态 0 回复与双向字节转发 |
| 面板 | `node --check web/app.js`；规则编辑器/分享链接源码检查，未做浏览器点击验收 |

## 0.24.0 账号生命周期验证（历史）

0.24.0 开发版在 macOS 27.0.1 arm64 通过 **339 项自动化测试（310 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器序列化回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 340 项。日志见 [verification-0.24.0.txt](verification-0.24.0.txt)，逐项清单见 [validation-evidence-0.24.0.json](validation-evidence-0.24.0.json)。

| 检查 | 结果 |
| --- | --- |
| Store | 本人改密错误当前密码 403；旧密码失效；其他会话失效、当前会话保留；管理员重置撤销全部会话/API 令牌；停用/启用；删除；自停用/自删除拒绝 |
| HTTP | 真实登录、改密、停用、启用、管理员重置、删除路由；旧密码 401、停用后 401、删除后 401；用户列表 `disabled` |
| 面板 | `node --check web/app.js` 通过；用户页/账户页新增改密、停用、删除按钮，未做浏览器点击验收 |

## 0.23.0 DNS 健康摘除验证（历史）

0.23.0 开发版在 macOS 27.0.1 arm64 通过 **337 项自动化测试（308 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器序列化回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 338 项。日志见 [verification-0.23.0.txt](verification-0.23.0.txt)，逐项清单见 [validation-evidence-0.23.0.json](validation-evidence-0.23.0.json)。

| 检查 | 结果 |
| --- | --- |
| 健康门控 | 绑定节点/规则；写入真实 `stats_json` 的健康报告，验证冷启动不创建、健康创建、不健康摘除、心跳过期摘除、恢复重建；`clear_health` 与 `min_keep` 有效 |
| 面板 | `node --check web/app.js` 通过；DNS 页新增健康节点/规则/清除字段，未做浏览器点击验收 |

## 0.22.0 DNS 托管记录验证（历史）

0.22.0 开发版在 macOS 27.0.1 arm64 通过 **336 项自动化测试（307 项 Rust、29 项 Python）**；DNS 核心为 3 项测试，健康门控在 0.23.0 增加。日志见 [verification-0.22.0.txt](verification-0.22.0.txt)，逐项清单见 [validation-evidence-0.22.0.json](validation-evidence-0.22.0.json)。

| 检查 | 结果 |
| --- | --- |
| DNS 单元/集成 | 3 项：mock Cloudflare 的创建、更新、观察不写、`min_keep` 保留/删除、服务商隔离；输入边界与回环 HTTP 规则；真实 HTTP 路由、令牌脱敏、租户管理员/API 令牌 403、DDNS 与删除清理 |
| 面板 | `node --check web/app.js` 通过；新增 DNS 页源码检查，未做浏览器点击验收 |
| 同步边界 | 只验证服务商 API 接受/返回；未连接真实 Cloudflare，未验证 DNS 传播、分页、供应商错误码矩阵、真实 Agent 端到端、webhook、权威池或污染/缓存 |

## 0.21.0 客户端订阅验证

0.21.0 开发版在 macOS 27.0.1 arm64 通过 **333 项自动化测试（304 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、编辑器序列化回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用。Linux 上还多一项条件单元测试，合计 334 项。日志见 [verification-0.21.0.txt](verification-0.21.0.txt)，逐项清单见 [validation-evidence-0.21.0.json](validation-evidence-0.21.0.json)。客户端订阅另有 `scripts/check_subscriptions.py` 的独立格式检查（真实控制器、公开端点、PyYAML/Base64 解析、轮换与删除）。

| 检查 | 结果 |
| --- | --- |
| 渲染单元测试 | 4 项：四种格式结构、跳过原因、宿主/标签/端口段/重名、令牌与过期 |
| Store/HTTP 集成 | 3 项：租户与系统管理员边界、持久化重开、真实公开端点、API scope、轮换/删除、60 次/分钟限频 |
| 独立格式检查 | `scripts/check_subscriptions.py` 启动真实控制器，发布 Shadowsocks 与普通 TCP 规则，分别拉取 V2Ray/Clash/Surge/Shadowrocket；PyYAML 解析 Clash，Base64 解码 V2Ray，核对预览跳过普通 TCP，轮换后旧链接 401、删除后 401 |
| 面板 | `node --check web/app.js` 通过；新增订阅页源码检查，未做浏览器点击验收 |

格式边界：只支持 Shadowsocks 入站；普通 TCP/TLS/WS 规则在 `skipped` 中明确说明。真实客户端矩阵、模板版本化、持久化分布式限频和反向代理审计仍未验收。

## 0.20.0 历史记录

0.20.0 开发版在 macOS 27.0.1 arm64 通过 **326 项自动化测试（297 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查、规则编辑器序列化回归与 Release 构建；另有一项崩溃子进程入口由父测试显式调用，不作为跳过项。Linux 上还多一项条件单元测试，合计 327 项。日志见 [verification-0.20.0.txt](verification-0.20.0.txt)，逐项清单见 [validation-evidence-0.20.0.json](validation-evidence-0.20.0.json)。完整 22 模块、两节点原生服务和长期负载验收仍在推进。

0.19.0 的历史计数需要更正：其开头的 318 项（289 + 29）来自 `--no-fail-fast` 的便携运行，没有计入 macOS 上失败的遥测与监听地址两项，也没有计入 1 项过滤；Linux 记录为 293 项 Rust（比 macOS 多一项条件测试）。0.20.0 已修复这两项 macOS 失败，并统一按完整套件计数。以下 0.19.0 记录保留原观测值。

## 0.20.0 审查修复验证

| 编号 | 修正 | 回归证据 |
| --- | --- | --- |
| R1 | 带 `advertise` 的规则参与用户跨节点份额，直接访问广告地址同样受限 | `review_regressions::advertised_listener_enforces_the_owners_limit_for_direct_clients`；1 MiB 双向在 16 KiB/s 限额下 1 秒未完成 |
| R2 | 份额按节点“期望修订 ∪ 已应用修订”计算；激活失败时 Agent 续租旧份额 | `review_regressions::rejected_revision_renews_the_running_limit_instead_of_removing_it`；端口冲突修订被拒绝后旧监听仍受限 |
| R3 | Shadowsocks TCP 盐缓存按（方式、密钥）跨兼容规则替换共享 | `review_regressions::shadowsocks_replay_state_survives_compatible_rule_revisions`；改名、限速、换钥三条路径 |
| R4 | 应用 schema v5、状态兼容代号 2；旧二进制拒绝打开，安装器拒绝跨代号回滚 | `recovery::application_schema_five_fences_downgrades_without_rewriting_tables`；`scripts/check_state_fence.py` 使用 0.18.0/0.19.0/0.20.0 三个真实二进制验证 MFA、迁移与 v4 备份恢复 |
| R5 | 规则编辑器保留 `target.draining`，并提供显式结束维护 | `scripts/test_web_editor.cjs` 执行随包 `targetEditor`，覆盖保留、显式关闭和普通目标 |
| R6 | macOS 遥测只要求流量样本；监听迁移按平台门控；故障切换改用确定性的 TLS 握手停滞 | `agent_reports_become_telemetry_visible_only_to_the_owning_tenant`、`listen_address_moves_between_one_address_and_all_addresses_on_the_same_port`、`stalled_primary_falls_back_within_one_connect_and_is_tried_last_afterwards` |

跨版本围栏脚本（本机，三个临时状态目录）：0.20.0 启用两步验证后密码登录 401；0.19.0 与 0.18.0 启动同一状态均以 `database schema newer than this binary` 退出；0.20.0 重新打开后密码登录仍 401、恢复码登录返回 200；撤销后的 API 令牌在重开前后均返回 401。0.19.0 创建的 schema v4 状态由 0.20.0 原地迁移，恢复日志序列 3→5→6 连续，旧二进制随后被拒绝。0.19.0 备份加日志由 0.20.0 `restore` 重放（备份序列 3、恢复序列 3），恢复后的控制器登录 200。

完整检查命令：

```sh
sh scripts/verify.sh
cargo build --locked --release
python3 scripts/check_state_fence.py --new target/debug/relay \
  --old /path/to/0.19.0/relay --legacy /path/to/0.18.0/relay
```

R1/R2 的毫秒数字只用于证明限额被明显突破或保持，不构成吞吐基准。跨版本脚本只操作本机临时状态，不调用服务管理器、真实安装器回滚或生产迁移。Linux 上仍应重跑完整套件、真实双机与 72 小时负载。

## 0.19.0 历史记录

0.19.0 开发版通过 **318 项自动化测试（289 项 Rust、29 项 Python）**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查与 Release 构建。日志见 [verification-0.19.0.txt](verification-0.19.0.txt)。本轮首次在 Linux 上构建并运行全部检查，新增管理账号两步验证与带权限范围的 API 令牌，并以真实浏览器验收相关页面。此前各版本的基准与演练记录保留在 [VALIDATION-0.18.0.md](VALIDATION-0.18.0.md) 等历史文件中；完整 22 模块、两节点原生服务和长期负载验收仍在推进。

## Linux 构建与测试

| 环境 | 结果 |
| --- | --- |
| Amp 云端沙箱：Debian 12 x86_64，2 核，3 GiB，Rust/Cargo 1.99.1，libclang 14 | 干净源码构建；`scripts/verify.sh` 全部通过（格式、Clippy、238 Rust、语法、28 Python），约 6 分钟；Release 构建约 4 分钟 |
| 用户 VPS：Debian 13 x86_64，4 核，7.8 GiB，Python 3.13.5，OpenSSL 3.5.7 | 在上述沙箱编译的 16 个测试程序全部通过（238 Rust，1 个崩溃子进程入口照常由父测试调用），约 63 秒；28 项部署测试以 root 运行通过，约 34 秒，只使用临时暂存目录，没有调用宿主服务管理器 |

首次 Linux 运行时，部署测试 `test_deploy_upgrade_and_rollback_preserve_every_runtime_byte` 因写死 127.0.0.1:8081 而失败（宿主上另一个程序占用该端口，监听预检正确拒绝）。测试已改为临时选择空闲端口。Debian 12 上构建的 Release 程序可直接在 Debian 13 上运行。

## 两步验证与 API 令牌

- 单元测试使用 RFC 6238 附录 B 的 SHA-1 测试向量（取低 6 位）和 RFC 4648 的 base32 向量，期望值独立于实现。
- HTTP 端到端测试覆盖：错误密码不能开始设置；待确认密钥不影响登录；错误验证码不能启用；启用后缺少验证码返回 `second_factor_required`，密码错误时不暴露两步验证状态；启用所用验证码及更早时间片不能重放；同一验证码只能使用一次；恢复码大小写、空格和连字符不敏感且只能使用一次；只读令牌不能写入、不能创建令牌或读取账户安全；写入令牌只能写所选资源；只读用户的写入范围令牌仍被拒绝；撤销令牌后立即失效；管理员重置他人两步验证并结束其会话与令牌，非管理员不能重置他人；停用需要密码和有效验证码；所有操作写入审计；10 次错误验证码后即使正确验证码也返回 429。
- 人为改动验证：去掉时间片防重放，或让范围检查恒为通过，端到端测试都会失败。
- 恢复演练：在启用两步验证后生成控制器备份，再创建 API 令牌，停止控制器后用备份和完整恢复日志执行 `relay restore`。恢复的控制器仍要求验证码；备份后创建的令牌可以读取，写入仍返回范围不足。

## 浏览器验收

使用无头 Chromium（1280×800 与 390×844）实际操作控制台：启用两步验证（再次确认密码、二维码、错误验证码提示、恢复码一次性展示）、登录时输入验证码、创建与列出 API 令牌、用户列表的两步验证状态与管理员重置、账户安全页的窄屏布局。二维码用 zbar 独立解码，内容与页面显示的密钥和 `otpauth://` 地址一致；启用和登录所用验证码由独立的 Python 实现生成。

同时发现并修复三个 0.18.0 已有的页面问题：节点注册成功后的一次性令牌对话框为空（关闭事件排队到新对话框打开之后才清空内容），修复后令牌和启动命令正常显示；窗口高度约 880 px 以下时固定侧栏不能滚动，“退出登录”无法点击；窄屏时面板标题按钮被挤成多行。规则编辑器、拓扑、额度和健康等其他页面本轮没有逐项验收。

## 两台 Linux 机器的实际转发

控制器、Agent A 和回显服务运行在 VPS 上，均只监听 127.0.0.1；Agent B 运行在云端沙箱，通过 SSH 隧道访问控制器。管理员登录后创建 `read`、`nodes:write` 范围的 API 令牌，之后的节点注册与规则发布全部使用该令牌。

- 两个节点都以严格租约注册并应用第 1 版配置。路径为：沙箱客户端 → Agent B → SSH 隧道 → VPS 上的 Agent A → 回显服务。
- 16 MiB 随机数据往返逐字节一致，约 72 Mbit/s 每方向；该数值包含 SSH 加密和两地网络，不是平台性能结论。
- 控制器账本中两个节点的规则各记录上传、下载 **16,777,281 字节**（16 MiB 加 65 字节探测），两跳计量一致。

第一次只验证了 TCP 隧道路径。之后在 VPS 防火墙临时只对沙箱出口地址放行 24680 端口（测试后已删除），验证了经公网的直接 TCP 和 UDP 路径：沙箱客户端 → Agent B → 公网 → VPS 上的 Agent A（`0.0.0.0:24680`）→ 回显服务。

- TCP：16 MiB 往返逐字节一致，约 168 Mbit/s 每方向（受两地网络限制，不是平台上限）。
- UDP：300 个 1200 字节数据包，0 丢失、0 损坏；往返中位数 31.1 ms、P95 35.2 ms、最大 46.8 ms，同时测得 ICMP ping 平均 30.0 ms，两跳转发约增加 1 ms。
- 账本：下行两节点一致；上行入口节点比出口节点多 1200 字节，即一个已被入口接纳但未到达出口的 UDP 包（公网丢失或测试中断时在途）。按每跳“已接纳负载”计量，这符合合同。
- 发现一处限制：把同一端口的监听地址从 `127.0.0.1:24680` 改为 `0.0.0.0:24680` 时，节点先绑定新监听再释放旧监听，因而拒绝应用（`cannot stage TCP listener`），并保留了原有可用版本。已修复，见下文“同一端口切换监听地址”。

这些仍不等于原生 systemd/OpenRC 服务、长时间负载或完整 WAN 性能验收。

## 转发性能、故障切换与配置下发

以下为 0.19.0 中持久预留计量、连接级故障切换和配置长轮询三项改动的实测。VPS 为 4 核、7.8 GB 的 Debian 13，release 构建，旧版为同一 0.19.0 改动前的二进制（SHA-256 `d33d9288…`）。

**本机回环转发**（`scripts/bench_loopback.py --mib 128 --rounds 5 --connections 1 4 16`，旧版与新版交替各跑两次，原始结果见 `benchmark-vps-meter-0.19.0-*.json`）。每个字节都校验，四次运行的账本均与实际转发字节完全一致。

| 场景 | 旧版 | 新版 |
| --- | ---: | ---: |
| TCP 单连接 | 2.6～3.2 Gbit/s（直连的 47～55%） | 约 5.0 Gbit/s（80～82%） |
| TCP 4 连接 | 约 5.6～5.8 Gbit/s | 约 5.4～5.6 Gbit/s（无明显变化） |
| TCP 16 连接 | 约 5.4～5.5 Gbit/s | 6.1～9.2 Gbit/s（波动较大） |
| UDP 往返中位数 / P95 | 275～391 / 800～1231 µs | 30～52 / 132～336 µs |

新版在 VPS 回环上出现少量内核接收队列丢包和重传（旧版几乎没有），推测是转发不再等待磁盘后更快填满 Python 回显服务的套接字缓冲；吞吐仍然提高。在 4 GB 内存的云端沙箱中，16 连接测试两个版本都因内核 TCP 内存压力出现数秒停顿，该环境不能用于比较 16 连接结果。

**故障切换**：自动测试使用接收队列已满、建连挂起的主目标和可用的后备目标，连接超时 2 秒。旧逻辑在 2 秒后断开客户端；新逻辑在同一次连接中转到后备目标（小于 1.8 秒），随后的新连接直接先试后备目标（小于 0.5 秒）。新缺省健康检查参数下约 2～4 秒摘除的数字是按参数推算的，尚未单独实测。

**配置下发**：两台机器环境（控制器在 VPS，Agent B 经 SSH 隧道连接），向 Agent B 发布新增规则 8 次，发布时刻随机。计时从发起发布请求开始，包括请求本身经隧道的往返。

| 指标 | 旧版（5 秒轮询） | 新版（长轮询） |
| --- | ---: | ---: |
| 新端口开始接受连接，中位数 / 最大 | 2.72 / 4.72 s | 0.16 / 0.18 s |
| 控制器显示已应用，中位数 / 最大 | 7.69 / 9.65 s | 0.16 / 0.18 s |

升级后同一路径 16 MiB 往返仍逐字节一致。

## 控制台新界面

0.19.0 重做控制台视觉：深色石墨底、单一橙色强调色、等宽数字与标签、细线边框和网格背景，并提供浅色主题（页眉按钮切换，选择保存在浏览器）。页面结构、接口和权限不变，只修改 `web/style.css`、登录页装饰与主题切换。在实际控制器（启用 `script-src 'self'; style-src 'self'` 内容安全策略）下加载，无脚本或样式被拦截。

用无头 Chromium 在 1440×900 和 390×844 下检查了登录、节点总览、转发规则、多跳拓扑、目标健康、共享额度、流量账本、用户与权限、账户安全和功能进度页，以及规则编辑对话框的深色与浅色主题；另录制了导航悬停、表格行悬停、主题切换和对话框键盘焦点。

检查中发现并修复：控制台显示的探测结果年龄包含节点上次回报以来的时间（缺省 5 秒轮询），新缺省有效期 5 秒会让正常目标显示为“结果过期”。缺省 `max_age_ms` 改为 10000；摘除速度由 1 秒超时和连续 2 次失败决定，不受影响。

## 运行总览与遥测

新增“运行总览”页，作为登录后的默认页面，原“节点总览”改名为“节点管理”。配色改为深海军蓝底、绿色强调色，浅色主题保留。所有数字取自 `GET /api/v1/telemetry` 与 `/topology`，每 5 秒刷新：吞吐由相邻回报的转发字节差值计算（多跳流量在每一跳各计一次），探测往返是节点到目标的探测耗时，不是中转增加的延迟；转发链路图按规则声明的 `via` 绘制，连线颜色取该段目标的最新探测结果。

在本机演示控制器（4 个已注册节点，其中 1 个离线；hkg → tyo → lax 三跳链路加持续流量）下，用无头 Chromium 检查了 1440×900 深色与浅色、390×844 深色，并录制了链路图节点悬停、点击节点进入该节点规则、节点表筛选。集成测试确认真实 Agent 的回报出现在遥测中，且其他租户的用户看不到。

检查中发现并修复：上游规则对下游中转的 UDP 健康探测原先每秒新建一个 UDP socket，下游按规则空闲超时（演示中 120 秒）保留每个来源端口的会话。演示中 lax-exit-01 的 UDP 会话数停在上限 64，丢弃 159 个数据报，上游 tyo-mid 的 UDP 目标因此在可用与不可用之间反复切换。现在探测成功期间复用同一 socket，下游只保留一个会话；回归测试在下游会话上限为 3 时连续探测 2 秒，修复前目标被判为不可用，修复后保持可用且下游只有 1 个 UDP 会话。

## 每连接内存

TCP 转发原先每个方向一开始就分配 64 KiB 缓冲。现在从 4 KiB 开始，读取填满缓冲时加倍，最多仍为 64 KiB；空闲或交互式连接保持小缓冲，大流量连接经几次读取后与原来相同。

在本机演示节点上建立 400 条 TCP 连接，各交换 5 字节后保持，测量 Agent 进程常驻内存（RSS）增量：

| 版本 | 第一轮 | 第二轮（复用已释放内存） |
| --- | ---: | ---: |
| 改动前 | 39.0 KiB / 连接 | 79.8 KiB / 连接 |
| 改动后 | 15.2 KiB / 连接 | 1.3 KiB / 连接 |

吞吐在 VPS 上用 `scripts/bench_loopback.py --mib 128 --rounds 5 --connections 1 4 16` 对比，旧版与新版交替各跑两次（`benchmark-vps-buffer-0.19.0-*.json`）。中转与直连之比：单连接旧版 74% / 82%、新版 80% / 76%；4 连接旧版 80% / 74%、新版 79% / 77%；16 连接两版都波动很大（旧版 68% / 16%，新版 61% / 82%）。没有观察到吞吐下降。

## 中转间预热连接

两台机器、经公网直连：云端沙箱客户端 → 沙箱 Agent B → 公网 → VPS 上的 Agent A → 回显服务。ICMP 往返 28.5 ms。VPS 防火墙临时只对沙箱出口地址放行测试端口，测完已删除。控制器与 Agent A 先升级到本版本（先控制器、后 Agent）。

两条规则交替各建 40 个新连接，每个连接发送 16 字节并等到回显，计时从发起连接到收到回显：

| 路径 | 中位数 | P90 | 最小 / 最大 |
| --- | ---: | ---: | ---: |
| 普通（每个客户端新建到 VPS 的连接） | 64.7 ms | 72.1 ms | 62.1 / 79.7 ms |
| 预热 4 条连接（PROXY v2，TLS 之前） | 33.4 ms | 36.2 ms | 31.4 / 39.0 ms |

每个新连接省去一个往返。这一跳没有 TLS；目标启用 TLS 且报头在 TLS 内时，TLS 握手也提前完成，可再省一个往返。测试期间 VPS 上保持 4 条等待报头的连接，回显服务没有收到空闲连接。

自动化测试覆盖：预热连接超过下游普通连接超时仍保持等待且不向目标转发；客户端由预热连接服务并在后台补足；下游重启关闭全部预热连接后，客户端改走新建连接仍然成功（去掉关闭检测后该测试失败）；发布时检查下一跳是否接受预热连接。

## 告警通知

- 单元测试：Webhook、飞书、钉钉签名与独立用 Python `hmac` 计算的值逐字节一致；UTC 时间格式覆盖闰日和 1970 年以前；同一问题在保持期内反复出现只算一个告警且不重复通知，保持期过后仍未恢复会再通知一次并写明反复次数；维护期间暂缓、结束后补发，维护期间出现又恢复的问题不通知；分组消息新问题和严重级别在前、最多列 10 条；编辑时留空的地址和密钥保留原值。
- HTTP 端到端测试：真实 Agent、真实目标和本地 Webhook 接收端。租户管理员读取返回 403，带写入范围的 API 令牌创建通道返回 403；响应不含密钥；留空密钥的编辑后测试消息签名仍正确；目标停止后收到带签名的告警，恢复后收到恢复通知；保持期内再次故障和恢复不发通知；发送记录、维护设置和删除通道正确。把保持期改为 0 后该测试失败。
- 演示控制器（3 个在线节点、1 个离线节点、4 个通道，其中 1 个指向不存在的地址）：停止回显服务 14 秒再启动。逐条发送时一次故障产生 26 条消息（13 个告警 × 2 个通道）；加入 5 秒分组后同一场景为 8 条。失败通道的错误显示完整原因（`Connection refused`）并按计划重试。控制台页面在 1440×900 深色、浅色与 390×844 下检查，包括添加与编辑对话框和维护模式。

告警状态和发送记录只在控制器内存中；邮件通道、按租户告警和自动化动作尚未实现。

## 同一端口切换监听地址

节点应用配置时仍先打开所有新监听，再关闭旧监听，任何失败都保留原版本。唯一的例外：新监听因“地址已被占用”失败，而占用者正是本节点即将移除、同端口同协议、其中一方为通配地址（`0.0.0.0` / `::`）的旧监听。这时先关闭这些旧监听再打开新监听，端口关闭的时间只有一次绑定；若新监听仍打不开，或随后写入本地配置失败，就重新打开旧监听并拒绝该版本。

曾考虑在交接期间给新旧 socket 都设置 `SO_REUSEPORT` 以避免这段间隙。在 Linux 6.1 与 6.12 上实测：交接本身可行，但 TCP 端口在交接后仍允许同一用户的其他进程用 `SO_REUSEPORT` 再绑定并分走连接，事后清除该选项也无效（UDP 无此问题）。因此没有采用。

- 自动化测试：TCP+UDP 规则在 `127.0.0.1:P` 与 `0.0.0.0:P` 之间来回切换，用 `127.0.0.2:P` 区分是否为通配监听；另一个程序占用 `127.0.0.2:P` 时切换到通配失败，TCP 与 UDP 旧监听都恢复、版本号不变，释放占用后重试成功。去掉恢复步骤后该测试失败。
- VPS 实测（Debian 13，Linux 6.12）：临时添加只接受本机来源的规则，在 `0.0.0.0:24684` 与 `127.0.0.1:24684` 之间切换 10 次，每次都被节点应用；期间客户端持续连接 `127.0.0.1:24684` 并收发数据，共 25,627 次连接、0 次失败。测试规则随后删除。

## 链路重启与节点重启后的恢复时间

演示环境中三跳链路 hkg → tyo → lax（每跳缺省健康检查：间隔 1 秒、连续 2 次成功、恢复观察 5 秒；入口到中转启用 4 条预热连接）。按多跳改向的规定流程先停用整条链路、再修改并启用，然后每 0.1 秒新建一个连接并收发数据：

| 版本 | 从启用到第一个成功连接 |
| --- | ---: |
| 改动前 | 约 16 秒 |
| 只去掉首次接纳前的恢复观察 | 3.8～4.8 秒 |
| 再加上首次接纳前 4 倍探测频率 | 0.6～1.1 秒（3 次） |

原因：每一跳的探测在下一跳就绪前失败，目标被判为不可用，之后恢复时还要等 5 秒恢复观察，三跳逐级叠加。曾经接纳、随后故障的目标仍然等待恢复观察。

重启入口节点 Agent（改动前后的程序各测 2 次）：带健康检查的规则恢复转发由 1.01 / 1.02 秒降到 0.26 / 0.26 秒；不带健康检查的规则两版都在启动后立即可用。

自动化测试：单元测试确认首次接纳前失败过的目标达到成功阈值即接纳，接纳后的故障仍进入恢复观察；集成测试中目标先失败、再恢复，在间隔 1 秒、恢复观察 5 秒的配置下 0.9 秒内被接纳（改动前该测试超时失败）。

## 丢包感知的最低延迟选路

- 单元测试：5 次探测（10、14 ms，失败，12、17 ms）得出窗口 5 次、失败 1 次、抖动 4.5 ms（失败隔开的两次不配对），选路耗时为 EWMA 加 200 ms；之后 20 次成功把失败挤出窗口。
- 集成测试：干净目标回复延迟 20 ms，另一个目标没有额外延迟但每 4 次探测失败 1 次（从不连续失败，因此保持“健康”）。`lowest_latency` 把所有新连接交给干净目标；去掉丢包折算后，新连接全部去了丢包目标，测试失败。
- 演示环境：在 `hk-web` 加入每 4 个连接丢弃 1 个的回显服务。节点上报 TCP 端点“探测通过”、最近 20 次失败 5 次（25%）、抖动约 0.15 ms；目标健康页的“耗时 / 丢包 · 抖动”列显示该值。该规则使用加权分配，所以丢包目标仍按权重分到连接；只有 `lowest_latency` 会据此避开它。

## 健康目标出现失败后加快复查

健康目标第一次探测失败后，下一次探测在间隔的四分之一后进行（与 HAProxy 的 `fastinter` 思路相同），而不是等满一个间隔；摘除之后恢复正常间隔。集成测试（间隔 1 秒、2 次失败摘除）：从第一次失败到摘除，改动前 1.00 秒（测试失败），改动后低于 0.6 秒；摘除后 1.5 秒内最多 2 次探测，确认没有持续高频探测已摘除的目标。

VPS 实测（Debian 13）：临时添加只接受本机来源的 UDP 规则，主目标优先级 0、后备优先级 1，缺省健康检查（间隔 1 秒、超时 1 秒、2 次失败摘除）。客户端每 20 ms 发一个包，停止主目标后记录到后备开始回复的间隔，每种情况 4 次：

| 主目标故障方式 | 改动前 | 改动后 |
| --- | ---: | ---: |
| 进程退出（系统回复端口不可达） | 1925 / 1985 / 1967 / 1965 ms | 730 / 1236 / 1238 / 1215 ms |
| 主机无回应（每次探测等满超时） | 2717 / 2954 / 2977 / 2975 ms | 2475 / 2989 / 2980 / 2982 ms |

无回应时由探测超时决定，两次超时约 2 秒，本改动不缩短；对近距离目标可把 `timeout_ms` 调低（例如 300 ms）来加快。测试规则随后删除。

## 加权分配避开丢包目标

集成测试：同优先级、相同权重的两个目标中一个每 4 次探测失败 1 次（保持“健康”），另有一个低优先级后备。窗口内失败达到 2 次后，该目标报告为 `degraded`，新连接全部交给干净目标（相同权重本应交替）；干净目标被摘除后，新连接改由降级目标承担，而不是跳到低优先级后备。去掉降级判断时测试失败。

## 节点总限速

集成测试：同一节点两条规则各回显 96 KiB（每条上下行合计 192 KiB），节点总限速 128 KiB/s。若按规则各自计速，两条约 0.5 秒即可完成；共用一个节点桶需 (384 − 128) / 128 = 2 秒，实测不少于 1.85 秒。随后发布取消限速的新修订，同样传输在 0.5 秒内完成。控制器测试确认：发布时省略该字段保留原值，`null` 取消，0 被拒绝。去掉节点桶或改为省略即清除时，对应测试失败。

VPS 实测（Debian 13，本机回环，`standalone` 模式两条规则发往同一接收端，单向，与在线测试规则隔离）：

| 节点总限速 | 两条规则合计 | 耗时 | 按限速推算 |
| --- | --- | --- | --- |
| 不限 | 2000 MiB | 0.51 s（约 33 Gbit/s） | — |
| 100 Mbit/s | 80 MiB（671 Mbit） | 6.16 s | 6.2 s |
| 1 Gbit/s | 800 MiB | 6.17 s | 6.2 s |
| 4 Gbit/s | 3000 MiB | 5.75 s | 5.8 s |

推算值扣除了开始传输前速率桶积累的约 0.5 秒额度（配置生效后桶从 64 KiB 起按限速回填）。实测与限速相差约 1% 以内。控制台演示环境另经控制器发布 40 Mbit/s：两条规则（其中一条经两跳链路）各回显 8 MiB 合计 5.71 秒，与“一秒突发 + 40 Mbit/s”推算的 5.7 秒一致；在控制台清空后恢复约 4 Gbit/s。

## 节点维护排空

集成测试：主目标（优先级 0）与后备（优先级 1）。保持一条到主目标的连接后将主目标设为排空：随后 3 条新连接全部到后备（排空的主目标排在更低优先级之后），原连接仍能收发；再把后备也设为排空，新连接回到主目标（全部排空时按优先级照常分配）。控制器测试用三跳链路排空中间节点：只有上游入口节点发布新修订，中间节点自身配置不变，不触发改向停止确认；重复排空不发布，排空无人指向的节点返回 409，结束维护后配置不再出现该字段。忽略排空标记，或把它算入路由结构时，对应测试失败。

## UDP 目标端口不可达时立即换目标

目标进程退出时，系统对发往该端口的包回复 ICMP 端口不可达，UDP 会话的发送或接收被拒绝。现在会话退出时把该目标排到其他目标之后 10 秒，下一个包直接走其他目标，不再等健康探测摘除。集成测试不配置健康探测，主目标关闭后客户端在 1 秒内（实测约 70 ms）收到后备的回复；去掉这一处理时，流量 3 秒内始终无法到达后备。

VPS 实测（Debian 13，`udp_failover.py`，客户端每 20 ms 发一个包，主目标停止到首个后备回复的间隔，4 轮）：

| 故障方式 | 改动前 | 改动后 |
| --- | --- | --- |
| 进程退出（系统回复端口不可达） | 713 / 1239 / 1244 / 1220 ms | 21 / 21 / 21 / 21 ms |
| 主机无回应 | — | 2479 / 2991 / 2993 / 2971 ms（不变，由探测超时决定） |

21 ms 即客户端的一个发包间隔：ICMP 回复让当前包丢失，下一个包已经由后备回答。

## 限速下的连接间公平

原先所有等待额度的会话各自计算等待时间后醒来争抢，先醒的拿走整块额度，部分连接长期只得到别人的一半。现在 4 KiB 及以上的读写按到达顺序排队，轮到时才取额度，读完再次排到队尾；小于 4 KiB 的读写不排队。总速率不变。

VPS 实测（Debian 13，`standalone` 模式节点总限速，批量连接持续上传到接收端，按接收端每条连接实际到达的字节计算 5 秒；另一规则每 20 ms 做一次 64 字节回显）：

| 限速 / 连接数 | 改动前 最慢 / 最快（Mbit/s） | 改动后 | 交互回显 p99 改动前 → 后 |
| --- | --- | --- | --- |
| 50 Mbit/s，4 条 | 9.3 / 14.5 | 12.5 / 12.5 | 1.77 → 1.51 ms |
| 50 Mbit/s，16 条 | 1.9 / 4.9 | 3.0 / 3.1 | 2.15 → 1.48 ms |
| 500 Mbit/s，16 条 | 27.4 / 34.6 | 31.1 / 31.4 | 1.55 → 1.57 ms |

总量在三种情况下均为限速值（49.9–500.1 Mbit/s）。集成测试：8 MiB/s 下 8 条连接 2 秒内最慢者不少于最快者的 80%（改动前三次分别只有约 45%、45%、35%），同时另一规则的小包回显在 40 ms 内完成（若小读写也排队，实测 126 ms）。

## Linux systemd 实机安装

VPS（Debian 13，systemd 257，x86_64）上用 `scripts/relay_deploy.py` 与临时签名密钥（私钥不离开构建机）打包两个版本（d098936 与 1f62e1d，状态兼容代号相同），独立于已有测试实例（控制器 127.0.0.1:18090，规则 127.0.0.1:24800）：

| 步骤 | 结果 |
| --- | --- |
| 验签、预检 | 通过，`ready: true` |
| 安装、启动、开机启用控制器 | 以 `relayp-controller` 运行，`ProtectSystem=strict`、`NoNewPrivileges`，状态目录 0700 |
| 注册节点、安装 Agent | 注册成功，但**每个配置都被拒绝**：`cannot enumerate local IPs for loop protection`（单元只允许 AF_UNIX/INET/INET6，列出本机地址需要 AF_NETLINK） |
| 升级到新包 | 程序切换成功，但单元文件未更新，问题仍在 |
| 修复后的安装器重新安装同一包 | 只替换单元文件；配置随即应用，TCP 64 MiB 双向校验通过，UDP 回显正确 |
| SIGKILL 控制器 | 转发不受影响，5 秒后重启（改动后 1 秒） |
| SIGKILL Agent | 新进程 5.1 秒后启动（改动后 1.05 秒）；转发在第 24.7 秒恢复，其余时间是等待旧严格租约过期 |
| 停止控制器 45 秒 | 转发第 25 秒中断，控制器启动后第 76 秒恢复（严格租约，见 LINUX_DEPLOYMENT.md） |
| 回滚 Agent 到上一代 | 身份、规则保留，4.6 秒恢复转发；修复后的单元文件保留 |
| 再次升级、卸载 | 升级后立即转发；卸载后无单元文件、端口关闭，状态目录保留 |

部署测试新增：Agent 单元必须允许 AF_NETLINK；新版服务模板在升级时写入，切换意图持久化后或选择切换后中断，`recover` 都能完成，相同包重新安装只替换服务文件。去掉替换逻辑时该测试失败。OpenRC 未在实机运行。

## 新建节点默认离线（可用优先）模式

依据上节实测（严格节点在控制器停止约 25 秒后中断全部转发），`POST /nodes` 省略 `lease_policy` 时改为离线模式，控制台“注册节点”默认选“可用优先”，租约窗口、暂停与到期字段随之禁用；`{}` 或 `{ttl_ms}` 仍创建严格节点。集成测试确认省略与 `null` 都得到离线节点、`{}` 得到 30 秒严格租约；恢复旧默认时该测试失败。已有节点的策略不变。

## 两台 VPS 实机（入口 + 出口）

两台 Debian 13 VPS 位于不同服务商，均用签名离线包和 `relay_deploy.py` 以 systemd 安装，节点为可用优先模式：VPS1（4 核）运行控制器（经 nginx HTTPS 对外）和入口节点，VPS2（1 核、715 MiB 内存）运行出口节点并以私有 CA 经 HTTPS 连接控制器。入口规则的主目标经 VPS2 出口（`via_node`），后备为 VPS1 本机回显；健康探测间隔 1 秒、超时 1 秒。两台 VPS 之间 ping 约 3 ms。

| 项目 | 结果 |
| --- | --- |
| 往返延迟（经中转 / 直连） | TCP p50 3.15 / 2.93 ms；UDP p50 3.40 ms，0 丢包；建连并收到首个回复 p50 6.6 / 6.8 ms |
| 大块传输（16 MiB 双向，校验内容） | 82–104 Mbit/s 每方向，直连 86 Mbit/s；出口计量 32.0 MiB，确认经过 VPS2；瓶颈是线路 |
| VPS2 资源 | Agent 常驻约 14 MB，传输期间不增长；含 32 MiB 转发在内共用 0.26 秒 CPU |
| SIGKILL 出口 Agent | 无失败请求；TCP 41 ms、UDP 51 ms 改走后备；1 秒后重启，新 TCP 10 秒后回到 VPS2 |
| 出口静默丢包 10 秒（iptables DROP） | 无失败请求；静默期间单个 TCP 连接最长 260 ms（竞速到后备），UDP 中断 2.6 秒（由探测摘除）；恢复 6.4 秒后新 TCP 回到 VPS2 |
| 停止控制器 45 秒 | 无失败请求，全部流量始终经 VPS2 |

**服务商丢弃 VPS1 端口段的回包。** 约每 50 个经 VPS2 的新连接有 1 个卡住 2.5 秒，随后 10 秒内的约 200 个连接全部改走后备。抓包显示 VPS2 收到 SYN 并回复 SYN-ACK（最多重发 8 次），VPS1 网卡上一个也收不到。指定本地端口逐一测试：VPS1 本地端口 30000–32000 发起的 TCP 连接 42/42 超时，两侧相邻端口全部正常，UDP 不受影响；VPS1 的地址转换保留端口号，不是端口改写所致。Linux 在 10000–65000 中随机选端口，所以 VPS1 约 3.6% 的出站 TCP（包括健康探测和其他服务）受影响。临时设置 `net.ipv4.ip_local_reserved_ports=30000-32000`（重启后失效）后 1500/1500 个连接经 VPS2，无卡顿。

程序据此改为**建链竞速**（见 HEALTH.md）：目标在对冲延迟内未连上时同时拨下一个候选，先连上者胜出；有探测的目标只因竞速落败不降级。在仍丢弃该端口段的线路上：卡顿从 2503 ms 降为约 253 ms，1500 个连接中 1458 个经 VPS2（改动前 1200 个中只有 145 个）。集成测试：主目标静默、5 秒连接超时时，首个连接在 1.6 秒内由后备完成（改动前 2.5 秒，测试失败）。

**升级丢失控制器 CA。** 出口 Agent 升级时未再次传 `--ca-certificate`，新代次没有 `ca.pem`，Agent 无法验证控制器证书，此后一直离线运行（转发不受影响，但收不到新配置）。安装器改为升级时沿用当前代次的 CA；部署测试在省略该选项的升级后检查新代次的 CA 与启动参数，去掉修复时失败。VPS2 显式传入 CA 重装后立即重新连上控制器。

### 远距离出口（第三台 VPS）

VPS2 在测试结束约 2.5 小时后从 VPS1 和外部都无法访问（所有端口完成握手但无任何数据，ping 不通，疑似服务商防护或停机，原因未确认）。入口规则持续把它判为不可用，全部流量走后备，无失败。另加一台 Debian 12 VPS3（1 核、960 MiB、systemd 252）作为远距离出口，与 VPS1 往返约 184 ms，同样用签名包安装（私有 CA 经 HTTPS 连控制器，可用优先）。入口规则改为 VPS2、VPS3 同优先级、`lowest_latency`，本机后备优先级 1；按 TOPOLOGY.md 先停用再改向，停用后 3 秒内确认并发布成功，VPS2 离线不影响入口节点的停止确认。

| 项目 | 结果 |
| --- | --- |
| 往返延迟（经中转 / 直连） | TCP p50 185.4 / 182.0 ms；UDP p50 172 ms，0 丢包；建连并收到首个回复 p50 366.5 / 363.6 ms |
| 大块传输（16 MiB 双向，校验内容） | 33–122 Mbit/s 每方向（多次波动），直连一次 88 Mbit/s；出口计量 32.0 MiB |
| VPS3 资源 | Agent 常驻约 13.5 MB；转发 32 MiB 用 0.22 秒 CPU |
| SIGKILL 出口 Agent | 无失败请求；UDP 126 ms 改走后备，最慢的 TCP 请求 785 ms；新 TCP 10 秒后回到 VPS3 |
| 出口静默丢包 10 秒 | 1 个失败：丢包开始时已经建立、正在等待回复的连接，客户端 3 秒超时（已建立的 TCP 不迁移）；此后新连接走后备，UDP 中断 2.9 秒；恢复 7.2 秒后新 TCP 回到 VPS3 |

TCP 探测延迟约 361 ms（建连加一次交换，两个往返），所以该目标的对冲延迟约 1.4 秒。systemd 252 忽略 `RestartSteps`、`RestartMaxDelaySec` 并记录警告，Agent 按 1 秒间隔重启，与 LINUX_DEPLOYMENT.md 所述一致。

### 30 分钟混合负载（VPS1 → VPS3）

VPS2 确认短期无法恢复后从入口规则移除（先停用再改向，3 秒内完成），入口只剩 VPS3 与本机后备。VPS1 上同时运行：20 个客户端不断新建 TCP 连接各做一次往返，4 条长连接每秒回显 16 KiB 并校验内容，10 个 UDP 会话每秒各 20 包；每 30 秒记录两端 Agent 的内存、CPU 与文件句柄。

| 项目 | 结果 |
| --- | --- |
| 新建 TCP 连接 | 64,964 次，0 失败；p50 341–365 ms（两个往返） |
| 长连接 16 KiB 回显 | 7,189 次，0 失败、0 内容错误 |
| UDP | 100,278 包，107 包 2 秒内无回复（0.11%），全部发生在第 13 分钟线路改道（往返从 184 ms 变为 170 ms）之后 |
| 资源 | VPS1 Agent 内存 14.4 → 15.9 MB，VPS3 14.0 → 15.0 MB，后半程平稳；CPU 约为单核的 7%（VPS1）和 3%（VPS3） |
| 负载中升级控制器 | 控制器停止到恢复服务 1.2 秒，该分钟无失败请求 |

事后同时比较经中转与直连的 UDP（各约 3,700 包）均无丢包，所以上述 UDP 丢包更可能来自改道期间的线路，但那段时间没有直连对照，未能证实。

改道时 VPS3 被短暂判为不可用，控制台只记录了“恢复可用”而没有“不可用”：故障与恢复都落在两次节点回报（5 秒）之间，控制器第一次看到的已是 `recovering`。现在由 `healthy` 直接变为 `recovering` 也记为不可用（单元测试在去掉修复时失败）；事件原因改用与健康页相同的中文（如“探测超时”），不再显示 `Io`、`Transport`。部署后在 VPS3 上丢弃入口流量 3 秒，控制台记录了“不可用；原因：探测超时”和 10 秒后的“恢复可用”。

控制台在无头 Chromium（1440×900）中逐页打开全部 13 个页面，无脚本错误。修复两处排版：运行总览的节点表在 1440 px 宽度下超出卡片 32 px，遮住“规则 →”列（吞吐小图改为 72 px）；直接放在卡片中的说明文字（共享额度页）没有内边距。

## 按用户公平分配与自适应探测超时

节点总限速打满时，大块读写原先按连接轮流，开 4 条连接的用户得到另一用户（1 条连接）的 4 倍。现在先在用户（规则所有者）之间轮流，再在同一用户的连接之间轮流。集成测试：8 MiB/s 节点上限，Alice 1 条连接、Bob 4 条，2 秒内两人所得相差不超过 20%；改回按连接轮流时 Alice 3.3 MB、Bob 13.4 MB，测试失败。原有按连接公平和小读写不排队的测试照常通过。

健康且最近至少 5 次成功的目标，每次探测最多等待最近最慢成功耗时的 2 倍（250 ms～`timeout_ms`），见 HEALTH.md。集成测试：间隔 1 秒、超时 1 秒的 UDP 目标突然不回应，固定超时下 3.0 秒才摘除，现在低于 1.8 秒（三次运行均通过）。单元测试覆盖样本不足、慢回复、上限、第一次失败后仍用短超时，以及摘除后恢复完整超时。

## 数万连接：出站端口不再全节点共用

在云端沙箱（2 核）用 `standalone` 模式建 3 条规则，各指向一个本机回显服务，客户端轮流向三条规则建立连接，每条连接回显 64 字节后保持空闲，最后抽查 500 条仍能回显（临时脚本，未收入仓库）。

| 目标连接数 | 改动前 | 改动后 |
| --- | --- | --- |
| 15,000 | 全部建立，185 MB | 全部建立，185 MB |
| 30,000 | 只建立 17,566 条，其余被重置 | 全部建立，360 MB |
| 45,000 | 26,212 条，抽查时部分连接已断 | 全部建立，531 MB，抽查全部回显 |

每条空闲连接约 11.6 KiB（以前 400 条小样本的 15 KiB 含启动开销）。原因：出站 TCP 套接字在连接前先绑定 0.0.0.0:0，内核此时不知道目标，只能分配全节点唯一的端口，所以一个节点同时只能有一个临时端口范围（沙箱缺省约 2.8 万）的出站连接，TIME_WAIT 中的端口也不能再用。现在绑定前设置 `IP_BIND_ADDRESS_NO_PORT`，端口在连接时按目标分配（与 HAProxy、Envoy 做法相同），不同目标可复用同一端口号。单元测试确认连接前不占端口；去掉该选项时测试失败。同一目标的并发连接仍受临时端口范围限制，这是 TCP 四元组本身的上限。UDP 会话各占一个本地端口，节点并发 UDP 会话数仍受临时端口范围限制。

### 4 小时负载（VPS1 → VPS3）与 UDP 直连对照

13:58–17:58 UTC，较轻的混合负载：8 个客户端不断新建 TCP 连接、1 条长连接每秒回显 16 KiB 并校验、4 个 UDP 会话各每秒 20 包。14:11 起在 VPS1 上用同样的 4 个 UDP 会话直接发往 VPS3 的回显服务（防火墙只放行 VPS1）作对照，持续 3.5 小时。

| 项目 | 结果 |
| --- | --- |
| 新建 TCP 连接 | 206,153 次，1 次失败：16:41 UTC 前后一次客户端 5 秒超时，该分钟 p99 升到 1.4 秒；控制台此时没有目标故障事件，原因未确认 |
| 长连接 16 KiB 回显 | 14,376 次，0 失败、0 内容错误 |
| UDP（重叠的 211 分钟） | 经中转 282,874 包丢 193（0.068%），直连 281,428 包丢 197（0.070%）；32 个有丢包的分钟两条路径同时丢包，数量相近，丢包来自两台 VPS 之间的线路 |
| 延迟（每分钟中位数，第一小时 → 最后一小时） | 新建 TCP p50 342 → 365 ms，UDP p50 170 → 181 ms，与线路改道一致；p99 基本不变（383 → 386 ms，192 → 191 ms） |
| 资源 | VPS1 Agent 15.9 → 16.0 MB、VPS3 Agent 15.0 → 15.0 MB，4 小时内不增长；CPU 约为单核的 7%（VPS1）和 3%（VPS3）；控制器 33 MB |
| 线路短时故障 | 14:12、14:16、14:34 三次 VPS3 被短暂判为不可用，5–11 秒后恢复，控制台均记录了“不可用”和“恢复可用” |

测试结束后用签名安装包把 b98ef34、6d28285、5a86b1d 部署到 VPS1（控制器、Agent）和 VPS3（Agent）：两个 Agent 重新连上控制器，配置修订一致且无应用错误，服务的 `LimitNOFILE` 为 1048576，VPS3 保留了私有 CA；300 个经入口的新连接全部由 VPS3 回复（p50 364 ms）。

## 跨节点用户总限速

系统管理员给用户设定总速率后，控制器在每次 Agent 同步时把它分成各节点的份额：发送在等额度的节点不断加份额，空闲节点保留 1/(8N)；新份额只占用其他节点已让出的部分。Agent 按同步请求发出时刻起保留份额 15 秒，连不上控制器时降到平均份额；控制器对 20 秒未同步的节点只按平均份额计算，刚重启的 20 秒内对未同步节点按持有全部速率计算。只计入口规则（声明 `advertise` 的后续一跳不计、不限）；已停用或到期的节点不占份额。

集成测试（真实 TCP 转发，两个 Engine 各一条同一用户的规则，控制器存储每 250 ms 同步一次，总速率 4 MiB/s，按接收端实际到达字节计 2 秒）：

| 阶段 | 节点 A | 节点 B | 合计 / 2 秒额度 |
|---|---|---|---|
| 只有 A 在发 | 7,864,320 | 0 | 93.75%（空闲节点保留 1/16） |
| 两个都在发 | 4,194,304 | 4,194,304 | 100%，各一半 |

连续 4 次：只有 A 在发时都是 7,864,320；两个都在发时 3 次各 4,194,304，1 次 A 多出 65,536（一次读写的大小）。另有：租户管理员不能设置或取消总限速（403）；从未同步的节点按预留份额列出，停用后不再占份额；后续一跳规则既不分配份额也不受限；取消总速率后下一次同步即解除。去掉 Agent 端限速，2 秒内 5.2 GB 通过；改成固定平均分配，只有 A 在发时只得到 50%；不排除停用节点，A 只得到 0；份额不按租约降级、后续一跳仍受限时，对应测试失败。控制器分配器的 5 项单元测试分别在去掉“只占已让出部分”、20 秒失联降级、重启保护、“流量中途停止且只用了不到一半份额不算忙”时失败。另一项测试启动真实 Agent 循环（HTTP 同步，常规轮询 3 秒）：设置总速率后，Agent 在下一次轮询拿到份额，之后 1 秒内再次同步并回报份额已生效，份额也写入 Agent 本地以便重启后恢复；拿到份额后仍按 3 秒轮询时测试失败。

VPS 实测（0.19.0 最终构建；VPS1 控制器 + 入口 Agent，VPS3 Agent）：`admin` 总速率 40 Mbit/s（5,000,000 B/s）。VPS1 用真实链路规则 `two-entry`（经 VPS3 到回显），VPS3 临时加一条本机入口规则 `three-user-test` 到本机回显；`three-exit` 声明了 `advertise`，按后续一跳不计。各用 2 条连接持续回显，按客户端每秒收到字节 × 2（上下行合计）计：

| 阶段 | VPS1 | VPS3 | 合计 / 总速率 |
|---|---|---|---|
| 只有 VPS1 在发（第 5–20 秒） | 4.66 MB/s | 0 | 93.1% |
| 两个都在发（第 25–40 秒） | 2.50 MB/s | 2.50 MB/s | 100.0% |
| 只有 VPS3 在发（第 45–60 秒） | 0 | 4.68 MB/s | 93.7% |

任一秒合计最高为总速率的 102.2%。VPS1 停止后 2 秒控制器把份额交给 VPS3，3 秒时 VPS3 达到 93%。VPS3 加入时有约 2 秒合计只有 56–61%：控制器先收回 VPS1 的份额，等 VPS1 下一次同步确认已按新份额执行后，才把这部分交给 VPS3，这是不超限的代价。

同一实测中修正了两处：空闲节点的实测速率原先每秒只减半，VPS1 停止后 VPS3 要 6–7 秒才升到 93%，现改为下降立即生效（上升仍取平均）；流量在一秒中途停止、只用了不到一半份额的节点不再算作“忙”。两处各有单元测试，改前失败。另外，旧测试节点 `svc-agent` 已不运行，却仍有该用户的启用规则，一直占 1/3 份额，对话框标为“未连接”；它是严格租约节点，停用后份额立即回到两台在用节点。测试结束后已删除临时规则、取消总速率，`svc-agent` 保持停用，真实链路复测 16 MiB 双向校验通过。

VPS3 本机回显压测中曾出现连接停滞：VPS3 内存 960 MB，内核 TCP 总内存上限 80 MB（`tcp_mem` 20550 页），而单个套接字缓冲上限被调到 64 MB，测试客户端不停写入，触发了 29 次 TCP 内存压力与 2,178 次接收队列丢包，本机连接重传退避到 6.5 秒。中转在下游写不动时停止读取上游，行为正确。客户端改用 256 KiB 缓冲后不再出现。大流量时同样的压力会影响该机所有 TCP 服务。

## 按最近探测中位数选最低延迟路线

`lowest_latency` 原先按探测耗时 EWMA（旧值 7/8）排序：一次 2 秒的慢回复让该目标的排序值上升约 244 ms，并持续多秒；持续的变化要十几次探测才生效。现改为最近 5 次成功探测的中位数（加原有丢包折算）。单元测试：5 次 50 ms 后一次 2 秒回复，选路值仍为 50 ms；改为持续 350 ms 后第 3 次生效；仍用 EWMA 时失败。

VPS 实测（VPS1 入口，临时规则两条同优先级路线：经 VPS3 出口到回显，探测约 365 ms；VPS1 本机可调延迟回显）。每 0.2 秒新建一个连接，记录走哪条路线；第 0 秒本机延迟 500 ms，第 20 秒改为 300 ms，第 30 秒让接下来两次健康探测回复各慢到 950 ms，第 50 秒改为 550 ms：

| | 旧版（EWMA） | 新版（中位数） |
|---|---:|---:|
| 本机变快后新连接改走本机 | 28.1 秒（第 30 秒的两次慢回复又推迟了切换；按公式无慢回复约 14 秒） | 2.4 秒 |
| 两次慢探测回复 | 旧版此时仍在 VPS3 上 | 不切换，30 秒内一直走本机 |
| 本机变慢后新连接改回 VPS3 | 4.4 秒 | 2.8 秒 |
| 失败连接 | 0 / 402 | 0 / 401 |

新版第一次运行中两次慢回复被测试连接而不是健康探测拿到，不能说明问题；改为只延迟探测请求（`PING`）后重测，上表为重测结果（慢回复计数归零，测试连接无一超过 800 ms）。测试结束后已停用并删除临时规则、停止可调回显，真实链路 16 MiB 双向校验通过。

## 多路聚合：按子流计时与避开静默失效的子流

VPS1 → VPS3 临时多路规则（mTLS，窗口 256 帧，retransmit_ms 500；各子流走同一条线路，往返约 184 ms），单连接回显，每轮 32 MiB，字节全部校验。

旧版固定 500 ms 重传间隔短于实际往返时间：VPS1 发送 318 MB 中有 41 MB 是未丢失帧的重复副本（failed_paths 为 0）。改为按 RFC 6298 实测计时（含 Karn 规则和超时退避），再改为每个子流各自计时：

| 每方向 Mbit/s（3 轮） | 旧版 482151d | 实测计时 ce3bb5b | 每子流计时 + 静默子流处理 |
|---|---|---|---|
| 普通单连接 | 85.7 / 93.1 / 92.7 | 86.4 / 81.5 / 89.6 | 84.9 / 85.0 / 89.9 |
| 聚合 1 子流 | 54.9 / 65.6 / 54.6 | 54.2 / 56.3 / 52.4 | 56.3 / 55.0 / 55.4 |
| 聚合 2 子流 | 61.4 / 66.7 / 63.8 | 57.7 / 62.0 / 69.5 | 66.4 / 62.1 / 61.9 |
| 聚合 4 子流 | 70.8 / 68.6 / 49.1 | 71.3 / 73.4 / 70.7 | 70.2 / 70.8 / 65.9 |
| 复制 2 子流 | 60.6 / 30.5 / 54.7 | 52.4 / 51.0 / 51.0 | 52.5 / 52.8 / 54.2 |
| 重传占发送（VPS1 / VPS3） | 41 / 318 MB（13%）/ 未记录 | 0 / 483 MB、0.36 / 480 MB | 0 / 446 MB、0.34 / 437 MB |

吞吐基本不变（同一线路上聚合不会超过普通单连接），但重复副本消失，4 子流和复制模式的波动变小。最后一列 2 子流第一次运行时上一个故障测试的防火墙规则仍未撤销，新会话按 min_paths 被拒绝，属预期；上表为重测结果。

故障测试：2 子流聚合传 128 MiB，约第 5 秒在 VPS3 上用 iptables 丢弃其中一个子流端口的包，持续到传输结束之后。无故障时 2 子流 8.6 秒、1 子流 15.5 秒，因此第 5 秒失去一个子流的理想耗时约 15 秒。

| 128 MiB 耗时 | 旧版 482151d | ce3bb5b | 新版 |
|---|---:|---:|---:|
| 单向丢包（VPS1 → VPS3 方向） | 47.9 秒（规则撤销后才恢复） | 31.1 秒 | 16.1 / 18.7 秒 |
| 双向丢包 | — | 30.4 秒 | 16.2 / 17.7 秒 |

单向丢包时反方向仍能把对端的帧继续送达约 6～8 秒，所以“又收到对端的帧”不能作为恢复依据；第一版按此恢复的实现实测 23.5 秒，已改为只发一个新帧试探、只经该子流发送的帧被确认才恢复。调试日志显示两端在丢包后 0.5～0.7 秒内都把该子流标为可疑，之后试探间隔按退避加倍。失去子流后仍有约 3～5 秒的低速期，原因尚未查明。单元测试模拟单向静默 1 秒的子流：旧实现两端各重传约 4.8 MB（占 12 MiB 的 40%），新实现被阻断的一端 0.56～0.77 MB、另一端 0.17 MB 以下，子流恢复后重新承载新帧。

## Shadowsocks 代理服务

互通：`scripts/check_shadowsocks_interop.py` 以 shadowsocks-rust 1.25.0 sslocal（官方发布包，已核对 SHA-256）为客户端，六种方式各传 4 MiB 双向并逐字节校验，IP 与域名目的地、半关闭均通过；默认策略拒绝回环、错误密钥、重放三项拒绝均通过（重放的第二次只收到 FIN，没有回复）；账本记录 51,118,540 字节，与应用数据完全相等，不含 Shadowsocks 帧开销。证据见 [shadowsocks-interop-0.19.0.json](shadowsocks-interop-0.19.0.json)。控制台“分享链接”生成的 2022 与旧版两种链接都直接用 `sslocal --server-url` 导入并传输成功；默认规则编辑器、启用 Shadowsocks 后隐藏目标与入口 TLS/WebSocket、编辑已有规则、普通规则创建均用真实浏览器检查。单元测试使用 sslocal 实际发出的请求字节：时间戳差 30 秒通过、31 秒拒绝，重放、篡改一字节、错误密码拒绝；分别去掉时间检查、盐记录或改为直接关闭连接，对应测试失败。

VPS 实测（VPS1 → VPS3，往返约 184 ms，2022-blake3-aes-256-gcm，sslocal 在 VPS1，VPS3 上对照运行官方 ssserver 1.25.0）：

| | 普通转发规则 | 本平台 Shadowsocks | 官方 ssserver |
|---|---:|---:|---:|
| 回显 32 MiB，每方向 Mbit/s（3 轮） | 约 97～99 | 88.1 / 89.1 / 88.6 | 77.1 / 91.6 / 76.1 |
| 新连接到首个回复（10 次中位数） | 340 ms | 341 ms | 342 ms |
| 经 Cloudflare 下载 50 MB（3 轮，MB/s） | — | 17.9 / 16.8 / 16.8 | 16.3 / 16.7 / 15.1 |

Shadowsocks 不增加往返：2022 版请求头随首个数据一起发出。下载受 VPS1–VPS3 单条长距离 TCP 限制，两台服务器各自直接下载约 97 MB/s。经 VPS1 入口规则转发到 VPS3 的 Shadowsocks 规则（默认策略）访问 Google、Cloudflare 正常，出口地址为 VPS3；访问 VPS3 的 127.0.0.1 与 169.254.169.254 被拒绝。测试后已停止临时客户端和官方服务端，删除临时规则，真实链路 16 MiB 双向校验通过。在 2 核沙箱本机回环上，本平台约 3.0～3.3 Gbit/s，官方服务端约 3.5～4.5 Gbit/s（客户端、服务端和回显共用 2 核，本平台含计量）。

### Shadowsocks UDP

互通：同一脚本经 SOCKS5 UDP ASSOCIATE 测试六种方式，0～60000 字节共 10 种长度的数据报逐字节回显，IP 与域名目的地、回复来源地址均正确；默认策略拒绝回环、错误密钥、2022 重放（第二份没有回复）通过；2022 关联在客户端换地址后把回复发往新地址；乱序到达的旧包号只接受一次；规则修改结束关联后，重放已收到过的数据报仍被丢弃，同一会话的新数据报照常转发（去掉“提前结束的关联保留包号”后此项失败）。账本记录 52,140,216 字节，与 TCP、UDP 应用数据之和完全相等。单元测试使用 sslocal 实际发出的 2022 AES、2022 ChaCha20 与旧版数据报：时间戳差 30 秒通过、31 秒拒绝，篡改、错误密钥拒绝；滑动窗口测试覆盖槽位复用（滑动时不清理当前槽位，测试失败）。控制台新建规则启用 Shadowsocks 时协议自动改为 TCP + UDP；用真实浏览器创建并发布到演示节点，修订 38 应用成功，TCP 与 UDP 同时监听；分享链接导入 sslocal 后经 UDP 向 1.1.1.1 查询 DNS 成功，访问 127.0.0.53 无回复。

VPS 实测（VPS1 → VPS3，往返约 170 ms，2022-blake3-aes-256-gcm，sslocal `-U` 在 VPS1，回显为 VPS3 本机 127.0.0.1:19100 的 UDP 回显服务，官方 ssserver 1.25.0 在 VPS3 上对照运行）：

| | 普通转发规则（VPS1 入口 → VPS3 出口） | 本平台 Shadowsocks | 官方 ssserver |
|---|---:|---:|---:|
| 64 字节往返，200 次中位数 / p95 / 丢失 | 169.7 / 170.9 ms / 0 | 169.8 / 171.5 ms / 0 | 182.1 / 197.6 ms / 3 |
| 1000 字节，提供 20 Mbit/s 时回显 | 18.7 Mbit/s（丢 6.4%） | 19.7（丢 1.5%） | 19.9（丢 0.6%） |
| 1000 字节，提供 50 / 80 Mbit/s 时回显 | 31.5 / 30.3 | 29.8 / 31.3 | 30.9 / 30.4 |
| 1200 字节，提供 5 Mbit/s 时回显 | 5.0（丢 0%） | 5.0（丢 0.27%） | 0（全部丢失，见下） |
| DNS 查询 1.1.1.1 / 8.8.8.8，20 次中位数 | — | 172.3 / 176.1 ms（经 VPS1 入口） | 173.2 / 173.4 ms（直连） |

- Shadowsocks UDP 不增加往返。提供 50 Mbit/s 以上时三条路径都停在约 30 Mbit/s，不是 Shadowsocks 造成：三条路径的回复都经 VPS3 → VPS1 这段线路，普通转发复测确认丢失发生在这段线路上（见下节）。
- VPS3 → VPS1 方向的路径 MTU 为 1280 字节（`ip route get` 显示缓存 mtu 1280）。官方服务端发送 UDP 时禁止分片，1200 字节负载加协议开销超过 1280，回复全部发送失败（日志 `Message too large (os error 90)`）；本平台与普通转发由内核分片后送达。
- 20 Mbit/s 时普通转发丢包高于 Shadowsocks（6.4% 对 1.5%）。普通路径经两跳中继（VPS1 入口、VPS3 出口），Shadowsocks 路径只经 VPS3 一跳；原因是每个 UDP 会话只有 4 个数据报的队列，见下节。
- 经 VPS1 入口转发到 VPS3 的 Shadowsocks 规则（默认策略）按域名访问 Google STUN，看到的公网地址为 VPS3 的 104.250.122.179；访问 VPS3 的 127.0.0.1:19100 与 169.254.169.254 没有回复，允许内网的对照规则有回复；同一规则的 TCP 正常（出口为 VPS3 的 IPv6）。测试后已停止临时客户端和官方服务端，删除 /run 下含密钥的临时配置，恢复原规则；真实链路 16 MiB 双向校验通过，55.8 Mbit/s。

### UDP 会话队列

监听端收到的数据报经队列交给各 UDP 会话（Shadowsocks 为各关联）。原队列只有 4 个数据报，突发或会话任务短暂未被调度时就丢包。现在每会话最多 256 个数据报、256 KiB，排队超过 50 ms 的数据报在取出时丢弃（计入丢弃计数），限速会话不会积压数秒延迟。集成测试：8 轮各 32 个 1200 字节数据报一次发出（共约 300 KB，超过一次可容纳的字节数），全部回显且丢弃为 0，旧队列下此测试失败；24 KB/s 限速规则一次收到 128 个数据报时丢弃排队过久者（去掉 50 ms 上限时测试失败）。去掉“取出时归还字节数”时第一个测试失败。

VPS 实测（VPS1 入口 → VPS3 出口 → VPS3 本机 UDP 回显，1000 字节，每次 10 秒，中继丢弃数取自两节点上报的计数）：

| 提供速率 | 修改前丢失 / 其中两中继丢弃 | 修改后丢失 / 其中两中继丢弃 |
|---|---|---|
| 20 Mbit/s（两次） | 4.54%、3.77%；共 2,079 个中 2,035 个 | 0.04%、0.08%；0 |
| 50 Mbit/s | 37.8%；23,617 个中约 10,300 个 | 38.8%～39.9%；0 |

本机两跳回环（同一程序内入口 → 出口 → 回显）：80 Mbit/s 由 1.05% 降为 0，200 Mbit/s 由 0.11% 降为 0.08%。

50 Mbit/s 时剩余丢失不在中继：VPS3 的 UDP 收发数相等（接收缓冲溢出 16 个），VPS1 发出的字节比收到的多约 23.7 MB，与丢失的约 2.4 万个数据报相符，而 VPS1 的接收缓冲溢出只有 1,096 个。即 VPS3 发回的数据报在两台服务器之间的网络上丢失，上表约 30 Mbit/s 的上限来自这段线路，而不是此前推测的 VPS3 单核 CPU 或 Python 回显服务。同一线路上 TCP 双向各约 55 Mbit/s，UDP 是否被服务商单独限速未验证。
