# 本地验证记录

0.9.0 开发版通过 **143 项自动化测试**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查和 Release 构建。完整测试清单与日志见 [validation-evidence.json](validation-evidence.json)、[verification-0.9.0.txt](verification-0.9.0.txt)。全部 22 个目标模块继续保留，本版本不是全功能最终版。

本轮新增声明式跨节点多跳、多入口与候选组、完整配置差异预览、控制器多节点事务发布，以及改向前的停止确认。数据模型、界面入口、API 和升级边界见 [TOPOLOGY.md](TOPOLOGY.md)。跨机器同时激活、真实业务健康和动态选路仍未完成。

## 自动化覆盖

| 组 | 通过数 | 主要覆盖 |
| --- | ---: | --- |
| 多节点拓扑 | 11 | 只读预览、完整发布、并发修订、整批回滚、租户隔离、协议/地址/范围匹配、多入口、候选组、声明环路、停止确认、监听复用与完整日志重放 |
| 控制与 Agent | 16 | 原有注册/同步/额度/恢复；新增三 Agent TCP/UDP、mTLS WSS + PROXY、停止后改向、节点应用失败保留旧链路 |
| 跨节点额度 | 12 | 层级额度、并发、幂等、整包、恢复隔离、归还和迟到消息 |
| 原转发引擎 | 16 | TCP/UDP、IPv4/IPv6、半关闭、ACL、均衡、限速、额度和配置失败 |
| 网络能力 | 16 | 端口范围/偏移、共享额度与会话上限、绑定、DNS TTL/负缓存、地址族与节点内环路 |
| PROXY 与 UDP 地址 | 19 | 报头/CRC、长度与格式、可信来源、ACL/哈希、TLS 顺序、逐包会话隔离及通配回复源地址 |
| WS/WSS | 20 | 独立帧样本、分片、半关闭、控制帧、反压、队列/时间边界、升级拒绝、额度和策略撤销 |
| 控制器日志 | 6 | 重放、损坏/截断/缺失拒绝、故障后拒写、状态与权限 |
| 账本与模型 | 8 | 用量、周期、租户、身份、配置修订和备份 |
| 对账与迁移 | 6 | 历史分页、重启、恢复标记、迁移和实例锁 |
| 合并提交 | 5 | 独立校验、整批持久化、幂等、拥塞和统计权限 |
| TLS | 7 | TLS 1.2/1.3、mTLS、错误证书拒绝、无明文回退和更新 |
| 突然退出 | 1 | 四个持久化边界启动真实子进程突然退出再恢复 |

另有一个 ignored 崩溃辅助入口，由父测试显式执行四次，不计作独立通过项；不是实机断电测试。网络集成使用真实本机套接字，WS 背压另用 Tokio duplex 精确控制缓冲。

新增网络测试分别运行三个真实 Agent 任务及独立数据库，经 HTTP 预览和发布三跳链路。验证 TCP 二进制与半关闭、UDP 原包、双向证书 WSS/PROXY 组合、持久化计量和方向反转。末节点额外监听被占用时，期望修订更新而实际修订保持旧版，错误可见，原链路仍能响应；停止链路后已有连接终止，再确认全部节点会话归零。

存储故障测试在最后一个节点配置写入处注入数据库失败，确认前面节点的修订、历史、规则绑定也回滚。恢复测试最初未关闭持有日志锁的 Store，离线恢复被正确拒绝；修正测试关闭顺序后通过，没有放宽生产锁。源码复查另补齐了拓扑页面标题映射，随后重新检查 JS 并构建 Release。Rust 行为未改动；以下 Release 功能和性能证据全部在最终二进制重跑。浏览器视觉与点击仍未验收。

## Release 三节点链路与恢复

本轮当前证据对应同一个 Release 二进制 SHA256；后文明确标注的旧版对照除外：

```text
7a1223432b79bbf7caa56598c2dfce14c55ea97e4f50952edb0509ea01a5cfbb
```

[三节点 CLI 记录](topology-smoke.json)使用一个控制器及**三个独立 Agent 进程**，各自保存状态。三种模式均在同一台 macOS 上运行；每组验证只读预览、整批发布、实际数据、停止确认、链路反转，再停止进程，从旧数据库备份和完整日志恢复新控制器。恢复后逐项核对拓扑、逐跳用量、旧登录会话及输入文件不变。

| 节点间模式 | 每跳应用账本 / 字节 | 三跳合计 / 字节 | 恢复重放事务 |
| --- | ---: | ---: | ---: |
| both | 69,152 | 207,456 | 31 |
| ws | 66,752 | 200,256 | 29 |
| wss | 66,752 | 200,256 | 31 |

`both` 为原生 TCP + UDP，`ws` 为 WS，`wss` 为双向证书 WSS；内部链路组合 PROXY v2/CRC，WSS 报头位于加密层内。每组正向 TCP 请求 33,333 字节并回显，反向链路请求 43 字节并回显；原生组另测 1,200 字节 UDP 往返。全部逐跳账本合计 **607,968 字节**精确匹配，封装不计入应用量。

这里是每跳独立计量：同一用户的三条规则会消费三份应用量。尚未实现逻辑流只计费一次。停止确认目前要求相关整节点无活跃会话，可能被无关规则阻挡。控制器一次事务提交期望配置不等于所有机器同时切换；声明图也不能发现所有 DNS/NAT 物理别名。

## 既有功能 Release 回归

- [普通 CLI](cli-smoke.json)：TCP/UDP 各 44 字节往返，共 **176 字节**，备份账本一致。
- [网络 CLI](cli-network-smoke.json)：两个连续入口按偏移映射，127.0.0.1/lo0 出口绑定，共 **352 字节**、一条共享规则记录，备份一致。DNS 行为由集成测试验证，该 CLI 使用 IP 目标。
- [PROXY 两跳 CLI](cli-proxy-smoke.json)：TCP/UDP 两规则共 **352 字节**，v2/CRC 报头不计费，备份一致。
- [HAProxy 互通](proxy-interop.json)：HAProxy 3.0.30 双向 TCP v1/v2/v2+CRC × IPv4/IPv6 原始地址，共 **18 种组合**、**294,912 字节**。核对地址、CRC、负载及半关闭；不代表外部 UDP/TLS/WS 组合均已验收。
- [独立 WS/WSS 互通](websocket-interop.json)：Python websockets 17.2 两端，WS/WSS/mTLS WSS 共 **3 种成功组合**，另有 **7 个拒绝用例**，应用计量 **1,573,086 字节**。临时私有 CA，验证双方半关闭、关闭握手和反向内容；不代表参考产品私有协议兼容。
- [旧控制器恢复](recovery-smoke.json)：从节点创建前的备份重放 **7 个事务（4→11）**，恢复身份、配置、旧会话；原 TCP 连接继续传输和补额。节点、控制器、预算记录均为 **286,720 字节**，有序停止归还未用预留。

四个示例配置均经最终 Release CLI 校验，WS 两跳示例还被性能脚本实际运行。验证进程均已停止，没有安装系统服务或修改系统网络。

## 本机回环性能

环境：macOS 27.0.1、arm64、Apple M1 Pro、10 逻辑 CPU、32 GiB，Rust/Cargo 1.99.1、Python 3.14.4。编译和功能检查结束后顺序运行基准；程序客户端和回显目标均在本机。吞吐使用单向应用字节除以完整往返验证时间，单位 Mbps，没有将双向字节翻倍作为好吞吐。

[独立转发](benchmark-local.json)：无 TLS，每连接 32 MiB，直连与转发交替 5 轮，持久化账本 **1,680,058,752 字节**精确一致。

| TCP 连接数 | 直连 / Mbps | 转发 / Mbps | 转发 / 直连 |
| --- | ---: | ---: | ---: |
| 1 | 13879.7 | 5041.6 | 36.3% |
| 4 | 13264.0 | 11128.6 | 83.9% |

UDP 每包 1,200 字节、100 次、0 失败；直连 RTT 中位 43.6 μs，转发中位 166.3 μs、P95 188.8 μs。此项绑定具体 IP，不是通配 packet-info 性能测试。

[原生两跳对比](benchmark-websocket.json)：同一 Relay 进程内的两条计量规则，节点间分别使用 TCP、WS、mTLS WSS。每连接 16 MiB、1 MiB 预热、4 轮，逐轮轮换模式顺序；没有跨节点共享额度。

| 并发连接 | 直连 | 两跳 TCP | 两跳 WS | 两跳 mTLS WSS |
| --- | ---: | ---: | ---: | ---: |
| 1 | 13187.2 | 3955.9 | 3763.0 | 3163.8 |
| 4 | 13340.9 | 9949.9 | 9315.4 | 7627.0 |

每种转发模式的两条规则合计 **1,346,371,584 字节**，原账本与备份完全一致。这是本机封装开销比较，不是三台机器的端到端吞吐，也不能推导 WAN 或单连接多路径增益。

[两 Agent 共享额度](benchmark-budget.json)：每连接 32 MiB、3 轮、4 MiB 预留，控制器恢复日志开启，默认最多 16 项合并、等待 2 ms。

| 总连接数 | 无全局额度 / Mbps | 共享额度 / Mbps |
| --- | ---: | ---: |
| 2 | 4930.7 | 399.8 |
| 8 | 4063.2 | 695.4 |

节点与控制器账本 **4,034,920,448 字节**一致，预算消费 **2,017,460,224 字节**，停止后未用预留 0。649 个同步请求合并为 543 批，最大单批 3 项，无拥塞拒绝或失败批次。

本组出现明显波动：8 连接普通路径单轮约 1.14～8.41 Gbps，开启额度约 0.69～1.39 Gbps。保留这组慢样本，并顺序追加每组 5 轮、8 总连接、同样 32 MiB/连接与 4 MiB 预留的当前版→旧版→当前版对照：

| 执行顺序 / 版本 | 无全局额度 / Mbps | 共享额度 / Mbps |
| --- | ---: | ---: |
| 1 · 0.9.0 | 9623.9 | 1312.6 |
| 2 · 0.8.0 | 10049.8 | 1328.6 |
| 3 · 0.9.0 | 9800.9 | 1293.2 |

原始数据分别见 [当前版首次对照](benchmark-budget-eight-connections-0.9.0.json)、[0.8.0 对照](benchmark-budget-eight-connections-0.8.0-recheck.json)、[当前版再次对照](benchmark-budget-eight-connections-0.9.0-after.json)。每组节点与控制器账本 **5,377,097,728 字节**精确一致。相邻对照没有复现持续的大幅下降，但不能证明性能等价或确定系统负载、磁盘同步等具体原因；小预留补额和运行间波动仍待优化。本轮没有同参考产品做同条件比较。

0.7.0 的两连接波动诊断、0.8.0 原始数据仍见 [0.7.0 验证](VALIDATION-0.7.0.md)、[0.8.0 验证](VALIDATION-0.8.0.md)。0.5.0 的 32 MiB 预留与合并提交对照属于历史，不能冒充本版本测量。

## 复现与未完成验收

```sh
sh scripts/verify.sh
cargo build --locked --release
python3 -m venv work/ws-interop
work/ws-interop/bin/python -m pip install -r scripts/requirements-interop.txt
work/ws-interop/bin/python scripts/check_topology.py --output artifacts/topology-smoke.json
work/ws-interop/bin/python scripts/check_websocket_interop.py --output artifacts/websocket-interop.json
work/ws-interop/bin/python scripts/bench_websocket.py --mib 16 --rounds 4 --output artifacts/benchmark-websocket.json
python3 scripts/bench_loopback.py --mib 32 --rounds 5 --output artifacts/benchmark-local.json
python3 scripts/bench_budget.py --mib 32 --rounds 3 --quantum-mib 4 --output artifacts/benchmark-budget.json
python3 scripts/check_recovery.py --output artifacts/recovery-smoke.json
python3 scripts/check_proxy_interop.py --haproxy /path/to/haproxy --output artifacts/proxy-interop.json
```

源码指纹包含 **64 个文件**，具体路径和算法见验证 JSON。Cargo 第三方元数据仍为 273 项，本轮没有新增平台依赖。Python websockets 仅在独立测试环境安装。最低 Rust 1.89 为声明值，本次仅验证 1.99.1。

- 用户已有 Linux 服务器，系统、架构和节点数量稍后提供；Linux 实机、独立机器部署、网卡权限、路由与 UDP packet-info 验收仍未完成。
- 管理页面只有源码与语法检查；浏览器此前拒绝本机地址访问，没有绕过，视觉与点击未验收。
- WAN、参考产品同条件比较、万级连接、72 小时混合负载、WS/WSS 实际 IPv6 线路和外部 UDP/TLS PROXY 互通仍未完成。
- 多跳灰度/跨机切换、真实业务探测、健康选路、规则级停止确认、逻辑流计费、MPTCP、多路径、组网、运营交易和共享等继续保留在完整清单。
- 自动证书续期、密钥轮换、完整额度灾难恢复、异常预留回收、全局限速、公平性、控制面高可用和异地日志仍有缺口。

源码、当前证据与历史慢样本一并保留。阶段性功能和短时回环吞吐不等于完整发布验收。
