# 本地验证记录

0.8.0 开发版通过 **130 项自动化测试**、Rust 格式检查、Clippy（警告视为错误）、JavaScript/Python 语法检查和 Release 构建。完整记录见 [validation-evidence.json](validation-evidence.json) 和 [verification-0.8.0.txt](verification-0.8.0.txt)。全部 22 个目标模块仍保留，本版本不是全功能最终版。

本轮新增入口及逐目标 WS/WSS、公开 `relay-stream-v1` 子协议、双向半关闭、有限缓冲与背压、HTTP 参数校验，以及与 TLS/mTLS、PROXY、统一计量的组合。协议合同见 [WEBSOCKET.md](WEBSOCKET.md)；既有地址和路由合同见 [PROXY.md](PROXY.md)、[ROUTING.md](ROUTING.md)。

## 功能验证

| 组 | 通过数 | 主要覆盖 |
| --- | ---: | --- |
| 跨节点额度 | 12 | 层级额度、幂等、整包、并发、恢复隔离、归还和迟到消息 |
| 控制与 Agent | 14 | 真实 HTTP 同步、两 Agent 额度、离线和恢复；HTTP 发布 PROXY、WS/WSS 字段到真实 Agent |
| 原转发引擎 | 16 | TCP/UDP、IPv4/IPv6、半关闭、ACL、均衡、限速、额度和配置失败 |
| 新网络能力 | 16 | 端口范围/偏移、共用额度与连接数、占用回滚、IP/网卡绑定、TTL/负缓存/零 TTL、地址族、静态/动态环路、旧连接保护、IPv6-only |
| PROXY 与 UDP 地址 | 19 | 独立报头/CRC、分片与长度、格式拒绝、可信来源、ACL/哈希、TLS/mTLS 顺序、逐包会话隔离及通配回复源地址 |
| WS/WSS | 20 | 独立线协议样本、分片、半关闭、Ping/Pong、反压、队列边界、关闭与空闲超时、错误升级/记录拒绝、额度、策略撤销、mTLS 与 PROXY 组合 |
| 控制器日志 | 6 | 重放、损坏/截断/缺失拒绝、故障后拒写、状态与权限 |
| 账本与模型 | 8 | 用量、周期、租户、身份、配置修订及备份 |
| 对账与迁移 | 6 | 历史分页、重启、恢复标记、迁移、实例锁 |
| 合并提交 | 5 | 独立校验、整批持久化、幂等、拥塞及统计权限 |
| TLS | 7 | TLS 1.2/1.3、mTLS、错误证书拒绝、无明文回退及更新 |
| 突然退出 | 1 | 四个持久化边界启动真实子进程突然退出再恢复 |

另有一个 ignored 的崩溃辅助入口，由父测试显式执行四次，未计为独立通过项；不是实机断电测试。网络集成使用真实本机套接字，有限缓冲另用 Tokio duplex 精确施加背压。IPv6 基础转发已有测试，本轮外部 WS/WSS 互通只使用 IPv4。

WS 测试覆盖 HTTP 报头与消息长度、非法记录、错误 Host/路径/Origin/子协议、无效握手密钥、错误 CA/服务名/缺少客户端证书、没有明文回退、解包后应用计量、收到 FIN 后继续回复，以及合并于升级响应之后的首帧。HTTP 发布到真实 Agent 的回归检查配置回读、非法协议发布不改变修订、实际两端 WS 数据和 20 字节账本。

复查发现：控制帧写入被对端阻塞时，Pong 刷出可能阻止关闭状态推进。用 64 字节 duplex 缓冲先复现超时失败，再为控制帧刷出加上截止时间；同一测试随全套通过。失败样本保留在 [回归记录](regression-ws-control-deadline-0.8.0.txt)。另外修复 Host 端口超过 65535 却未被 Authority API 检出的输入校验问题。

## Release 互通、CLI 与恢复

所有本轮证据均对应相同 Release 二进制 SHA256：

```text
50365b3987d7581de15a877a23c0574b3031f9f47955c77fa62731234d67aa13
```

- [独立 WS/WSS 互通](websocket-interop.json)：Python websockets 17.2 客户端 → Relay → Python websockets 17.2 服务端。WS、WSS、双向证书 WSS 共 3 种成功组合，每组请求 262,181 字节，收到完整 FIN 后将内容反转回传，核对双方半关闭与正常关闭握手。另有 7 个错误 Origin/子协议/缺少客户端证书的拒绝用例。总应用账本 **1,573,086 字节**精确匹配，封装和控制帧未计费。使用临时私有 CA，不是公网证书或第三方私有隧道兼容验收。
- [普通 CLI](cli-smoke.json)：TCP/UDP 各 44 字节往返，共 **176 字节**，备份账本一致。
- [网络 CLI](cli-network-smoke.json)：两个连续入口按偏移映射，127.0.0.1/lo0 出口绑定，共 **352 字节**且只有一条共享规则计量记录；备份一致。IP 字面量目标只验证 DNS 缓存配置加载，DNS 实际行为由网络集成测试验证。
- [PROXY 两跳 CLI](cli-proxy-smoke.json)：TCP/UDP 两条规则各 **176 字节**，共 **352 字节**，PROXY v2/CRC 报头不计费，备份一致。
- [HAProxy 互通](proxy-interop.json)：在当前二进制上重跑 HAProxy 3.0.30 双向 TCP v1/v2/v2+CRC × IPv4/IPv6 原始地址的 **18 种组合**，独立核对地址、CRC、负载、半关闭及 **294,912 字节**账本。它只验证明文 TCP PROXY；WS/WSS 与 PROXY 的组合使用原生节点集成测试，不宣称 HAProxy 的 TLS/UDP/WS 组合均已验收。
- [旧备份恢复](recovery-smoke.json)：CLI 从节点创建前的备份重放 7 个事务（序号 4→11），恢复节点身份、配置和旧会话；原 TCP 连接在控制器替换后继续传输和补额。节点、控制器与额度记录均为 **286,720 字节**；输入不变，有序停止归还未用预留。

四个示例配置均经当前 Release CLI 校验。WS 两跳示例同时由下面的原生两跳基准真实运行并核对备份。所有测试子进程已停止；没有安装系统服务或改动系统网络。

## 本机两跳 WS/WSS 性能

环境：macOS 27.0.1、arm64、Apple M1 Pro、10 逻辑 CPU、32 GiB 内存、Rust/Cargo 1.99.1、Python 3.14.4。先完成构建和功能测试，再顺序执行各基准。程序客户端和目标均为本机 Python TCP，入口与出口为同一 Relay 进程内的两条规则，各有持久化计量。仅两条规则之间的连接分别使用 TCP、WS、双向证书 WSS；没有跨节点共享额度。

[原始两跳数据](benchmark-websocket.json)：每连接 16 MiB，每种模式先预热 1 MiB，1/4 条连接各 4 轮，每轮轮换直连、TCP、WS、WSS 的执行顺序。中位吞吐按单向应用字节除以完整往返验证时间计算，单位 Mbps；不是把上下行合计为双倍吞吐。

| 并发连接 | 直连 | 两跳 TCP | 两跳 WS | 两跳 mTLS WSS |
| --- | ---: | ---: | ---: | ---: |
| 1 | 12466.7 | 3881.3 | 3419.7 | 3021.3 |
| 4 | 13859.0 | 9904.4 | 9208.3 | 7905.6 |

每种转发模式的两条规则合计 **1,346,371,584 字节**，三种模式都逐字节验证、精确核对两条账本及备份。该短基准显示本机 WS/WSS 封装开销，不能推导广域网吞吐、单连接多路径增益或 Linux 容量。没有与参考产品进行同条件比较。

## 既有路径性能回归

[普通独立转发](benchmark-local.json)：无 TLS，每连接 32 MiB，直连与转发交替测量 5 轮，账本 **1,680,058,752 字节**精确匹配。

| TCP 连接数 | 直连 / Mbps | 转发 / Mbps | 转发 / 直连 |
| --- | ---: | ---: | ---: |
| 1 | 13769.1 | 5065.9 | 36.8% |
| 4 | 12669.8 | 11014.1 | 86.9% |

UDP 每包 1200 字节、100 次、0 失败；直连 RTT 中位 42.2 μs，转发中位 168.3 μs、P95 190.5 μs。未启用 PROXY，UDP 绑定具体 IP，不是通配 packet-info 的性能测试。

[真实两 Agent 共享额度](benchmark-budget.json)：每连接 32 MiB、3 轮，4 MiB 预留，控制器恢复日志开启，合并最多 16 项、等待 2 ms。无全局额度组也有持久化规则计量。

| 总连接数 | 无全局额度 / Mbps | 共享额度 / Mbps |
| --- | ---: | ---: |
| 2 | 5100.2 | 626.9 |
| 8 | 9255.0 | 1355.7 |

节点与控制器账本合计 **4,034,920,448 字节**精确一致，预算组消费 **2,017,460,224 字节**，停止后未用预留 0。601 个同步请求合并为 329 个批次，最大单批 3 项，无拥塞拒绝或失败批次。小预留补额仍有明显开销，尚未达到完整性能目标。

0.7.0 两连接补额曾有较大波动，相关新版→旧版→新版诊断原始样本继续保留于 [0.7.0 验证记录](VALIDATION-0.7.0.md)，没有因为这次中位值较高而删去此前较慢结果。0.5.0 的 32 MiB 预留与控制合并对比也是历史数据，本轮未重跑，不能冒充 0.8.0 测量。

## 复现与剩余门槛

```sh
sh scripts/verify.sh
cargo build --locked --release
python3 -m venv work/ws-interop
work/ws-interop/bin/python -m pip install -r scripts/requirements-interop.txt
work/ws-interop/bin/python scripts/check_websocket_interop.py --output artifacts/websocket-interop.json
work/ws-interop/bin/python scripts/bench_websocket.py --mib 16 --rounds 4 --output artifacts/benchmark-websocket.json
python3 scripts/bench_loopback.py --mib 32 --rounds 5 --output artifacts/benchmark-local.json
python3 scripts/bench_budget.py --quantum-mib 4 --output artifacts/benchmark-budget.json
python3 scripts/check_recovery.py --output artifacts/recovery-smoke.json
python3 scripts/check_proxy_interop.py --haproxy /path/to/haproxy --output artifacts/proxy-interop.json
```

源码指纹在本轮将 `examples/` 也纳入，具体 60 个文件及算法见验证 JSON。Cargo 元数据有 273 个第三方依赖条目；Python websockets 只在独立测试环境安装，不属于平台运行时依赖。包声明最低 Rust 1.89，本次仅验证 Rust 1.99.1。

- 用户已有 Linux 服务器，系统、CPU 架构和节点数量将稍后提供；Linux 实机、两节点部署、网卡权限与实际路由、UDP packet-info 验收仍未完成。
- 浏览器对本机地址的访问此前被权限检查拒绝，没有绕过；管理页面只有源码与语法检查，视觉与点击尚未验收。
- 未完成 WAN、参考产品同条件对比、万级连接、72 小时混合负载、WS/WSS 实际 IPv6 线路和外部 UDP/TLS PROXY 互通。
- 自动证书续期、密钥轮换、跨节点多跳图、聚合、组网、交易与其余 22 模块缺口继续保留。完整额度灾难恢复、异常预留回收、跨节点限速、控制面高可用和异地日志也未完成。

此前版本证据保留为版本化文件。阶段性功能、测试通过和短时回环吞吐不等于完整发布验收。
