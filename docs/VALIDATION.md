# 本地验证记录

0.7.0 开发版通过 **109 项自动化测试**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查和 Release 构建。记录见 [validation-evidence.json](validation-evidence.json) 和 [verification-0.7.0.txt](verification-0.7.0.txt)。完整目标尚未完成。

本轮新增 TCP PROXY v1/v2、逐包 UDP v2、CRC32C、TLS 内外报头顺序、可信实际对端与声明来源的区分，以及通配 UDP 的实际目的地址和回复源地址。合同与升级边界见 [PROXY.md](PROXY.md)，此前网络能力见 [ROUTING.md](ROUTING.md)。

## 功能验证

| 组 | 通过数 | 主要覆盖 |
| --- | ---: | --- |
| 跨节点额度 | 12 | 层级额度、幂等、整包、并发、恢复隔离、归还和迟到消息 |
| 控制与 Agent | 13 | 真实 HTTP 同步、两 Agent 额度、控制器替换、离线和恢复；HTTP 发布 PROXY 配置到真实 Agent |
| 原转发引擎 | 16 | TCP/UDP、IPv4/IPv6、半关闭、ACL、均衡、限速、额度和配置失败 |
| 新网络能力 | 16 | 端口范围/偏移、共用额度与连接数、占用回滚、IP/网卡绑定、TTL/负缓存/零 TTL、地址族、静态/动态环路、旧连接保护、IPv6-only |
| PROXY 与 UDP 地址 | 19 | 独立报头/CRC 样本、分片与最大长度、格式拒绝、可信来源、ACL/哈希、TLS/mTLS 顺序、逐包会话隔离、实际回复源地址及策略更新 |
| 控制器日志 | 6 | 重放、损坏/截断/缺失拒绝、故障后拒写、状态与权限 |
| 账本与模型 | 8 | 用量、周期、租户、身份、配置修订及备份 |
| 对账与迁移 | 6 | 历史分页、重启、恢复标记、迁移、实例锁 |
| 合并提交 | 5 | 独立校验、整批持久化、幂等、拥塞及统计权限 |
| TLS | 7 | TLS 1.2/1.3、mTLS、错误证书拒绝、无明文回退及更新 |
| 突然退出 | 1 | 四个持久化边界启动真实子进程突然退出再恢复 |

另有一个 ignored 的崩溃辅助入口，由父测试显式执行四次，未计为独立通过项。未进行实机断电验证。

网络测试使用真实本机套接字及可变回答的 DNS 服务。验证了 1 秒响应 TTL、30 秒响应被配置上限缩短、NXDOMAIN 负缓存过期、0 秒禁用正缓存，以及 DNS 由正常回显地址变为本机监听时被阻止。相同配置跨规则共享缓存；IPv4/IPv6 地址选择和实际目标观察到的源 IP 均有检查。

旧配置中的 A→B 连接仍存活时，新方向 B→A 被保守拒绝；旧连接正常转发并结束后，新无环方向可以使用。此项没有扩大为跨 Agent 或 NAT 环路保证。

0.6.0 为避免测试监听与临时出站端口竞争而调整的端口选择仍保留。本轮另外复现：将同一 PROXY 策略在两个既有目标之间移动时，只比较非空策略列表会漏掉旧会话撤销。现按目标地址检查策略变更，该真实连接回归随全套测试通过。

Rust TLS 组合测试覆盖 v1/v2 × TLS 外/内报头和 mTLS，独立 TLS 客户端验证缺少客户端证书时被拒绝。UDP 覆盖同一代理承载多个原始客户端、不同代理声明相同地址、每包校验、空负载和 IPv4/IPv6 通配回复源地址。这些本机测试不等于 Linux 或外部 UDP/TLS 实现互通。

## Release CLI 与恢复

[普通 CLI](cli-smoke.json)：TCP/UDP 各 44 字节往返，持久化接纳总计 176 字节，备份账本一致。

[新网络 CLI](cli-network-smoke.json)：两个连续入口按偏移分别转发至两个目标，同时设置 127.0.0.1/lo0 出口绑定和系统 DNS 缓存配置。两个入口分别通过 TCP/UDP 探测，共 352 字节，只有一条共享规则计量记录；备份与原账本一致。目标是 IP 字面量，因此 CLI 此项确认系统缓存配置可加载；实际 DNS 缓存行为由网络集成测试验证。

[PROXY 两跳 CLI](cli-proxy-smoke.json)：实际运行 `examples/proxy-hop.json` 的两跳模型，入口/中继端口在临时副本中调整；TCP/UDP 探测均成功。两条规则各记录 176 字节，共 **352 字节**，未计入 PROXY v2/CRC 报头；备份账本一致。

[HAProxy 互通](proxy-interop.json)：使用官方源码校验和一致的 HAProxy 3.0.30，本机编译而未安装，未链接进平台。Python → HAProxy → Relay → HAProxy → Python 的双向链路，入口和出口各采用 v1、v2、v2+CRC，结合 IPv4/IPv6 原始地址，共 **18 种组合**。独立 Python 观察端校验原始地址、CRC32C、二进制负载和半关闭。账本精确为 **294,912 字节**，所有验证子进程停止；此项仅为明文 TCP 功能互通。

[恢复演练](recovery-smoke.json)：在节点创建前备份，随后通过实际 Agent 转发并消费额度。CLI 从旧备份重放 7 个事务（序号 4→11），恢复节点身份、配置及旧 API 会话。原 TCP 连接在控制器替换后继续传输和补额；节点、控制器和额度记录均为 **286,720 字节**。输入备份/日志保持不变，有序停止归还未用预留。所有验证子进程已停止。

## 本机回环性能

环境：macOS 27.0.1、arm64、Apple M1 Pro、10 逻辑 CPU、32 GiB 内存、Rust/Cargo 1.99.1、Python 3.14.4。以下本轮数据使用同一 Release 二进制、无 TLS、Python 回显服务。先完成编译/测试，再顺序执行基准；没有参考产品或广域网比较。

[独立转发](benchmark-local.json)：每连接 32 MiB，直连与转发交替，共 5 轮，中位值如下。所有载荷逐字节验证，持久化账本 **1,680,058,752 字节**完全匹配。

| TCP 连接数 | 直连 / Mbps | 转发 / Mbps | 转发 / 直连 |
| --- | ---: | ---: | ---: |
| 1 | 14623.9 | 5251.7 | 35.9% |
| 4 | 16154.3 | 11452.6 | 70.9% |

UDP 每包 1200 字节、100 次、0 失败；直连 RTT 中位 41.4 μs，转发中位 164.5 μs、P95 182.0 μs。此基准未启用 PROXY，UDP 绑定具体 IP，不是新协议或通配 packet-info 路径的性能测试。

[真实两 Agent 共享额度](benchmark-budget.json)：每连接 32 MiB、3 轮；控制器恢复日志启用，最多 16 项合并提交、等待 2 ms；单次预留 4 MiB。无全局额度组也启用持久化规则计量。

| 总连接数 | 无全局额度 / Mbps | 启用共享额度 / Mbps |
| --- | ---: | ---: |
| 2 | 4598.9 | 366.3 |
| 8 | 10074.8 | 1256.1 |

节点与控制器账本合计 **4,034,920,448 字节**完全一致；预算组消费 **2,017,460,224 字节**，停止后未用预留 0。同步统计为 606 请求、359 批次、最大单批 4 项，无拥塞拒绝和失败批次。

两连接首轮结果低于 0.6.0 历史中位值 585.2 Mbps，因此追加同条件诊断：同一脚本、每连接 32 MiB、4 MiB 预留，每组 5 轮，按下列顺序执行。旧二进制 SHA256 与 0.6.0 记录一致，没有重新编译或改配置。

| 顺序 | 二进制 / 原始数据 | 无全局额度 / Mbps | 共享额度 / Mbps |
| --- | --- | ---: | ---: |
| 1 | [0.7.0 补测](benchmark-budget-two-connections-0.7.0.json) | 4312.5 | 345.4 |
| 2 | [0.6.0 重测](benchmark-budget-two-connections-0.6.0-recheck.json) | 4840.1 | 371.3 |
| 3 | [0.7.0 再测](benchmark-budget-two-connections-0.7.0-after.json) | 3952.2 | 605.0 |

三组各自核对 **1,350,565,888 字节**账本，停止后剩余预留均为 0。首轮较低的 366.3 Mbps 样本保留为主报告，未用较快补测覆盖。不同轮次波动较大，顺序重测没有隔离全部主机负载、调度和磁盘同步时序，不能证明新旧性能等同，也不能将首轮下降归因于 PROXY 改动。

小预留批次的全局额度仍显著降低吞吐，稳定性和补额调度继续待优化。本轮数值不能证明“性能最强”。0.5.0 的控制 API 合并开关对比与 32 MiB 预留结果保存在对应 `-0.5.0.json` 和 [VALIDATION-0.5.0.md](VALIDATION-0.5.0.md)；本轮没有重复这些对比。0.6.0 原始结果保留于 `-0.6.0.json` 和 [VALIDATION-0.6.0.md](VALIDATION-0.6.0.md)，与上面的旧二进制重测分别记录。

## 尚未通过的门槛

- Linux 实机与两节点部署，特别是网卡绑定权限、UDP packet-info、真实路由和 IPv6 链路本地场景。
- 浏览器视觉、点击和移动端布局；本机地址的浏览器访问曾被拒绝，没有绕过限制。页面源码和语法检查不等于交互验收。
- 同条件 Realm 基准、真实 WAN、TLS/PROXY 压力、万级连接、72 小时混合负载；外部 UDP/TLS PROXY 互通。
- 跨节点拓扑、MPTCP、多路径聚合、商业、订阅、组网、DNS 管理与共享等完整范围。
- 异常预留恢复、周期调度、分布式租约、跨节点总速率与公平性、异地日志/归档和密钥迁移。

没有完整大模块在此阶段宣布全部验收。完整清单见 [REQUIREMENTS.md](REQUIREMENTS.md)，后续顺序见 [STATUS.md](STATUS.md)。

## 可重跑命令

```sh
sh scripts/verify.sh
cargo build --locked --release
cargo test --locked --test proxy_protocol
./target/release/relay validate --config examples/proxy-hop.json
python3 scripts/check_proxy_interop.py --haproxy /path/to/haproxy --output artifacts/proxy-interop.json
python3 scripts/bench_loopback.py --mib 32 --rounds 5 --output artifacts/benchmark-local.json
python3 scripts/bench_budget.py --quantum-mib 4 --output artifacts/benchmark-budget.json
python3 scripts/check_recovery.py --output artifacts/recovery-smoke.json
```
